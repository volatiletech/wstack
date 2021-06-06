package servers

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/friendsofgo/errors"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/acme/autocert"
)

// Default timeout values if not overridden using WithTimeout.
const (
	// readTimeout also sets idleTimeout
	readTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
)

// serverErrLogger allows us to use the zerolog.Logger as our http.Server ErrorLog
type serverErrLogger struct {
	logger zerolog.Logger
}

// Implement Write to log server errors using the zerolog logger
func (s serverErrLogger) Write(b []byte) (int, error) {
	s.logger.Error().Str("error", string(b)).Msg("server error")
	return 0, nil
}

// Builder is a configuration builder function.
type Builder func(*Config) error

type Config struct {
	router http.Handler

	httpBind string

	httpsBind string
	tlsKey    string
	tlsCert   string
	tlsConfig *tls.Config

	letsEncryptManager *autocert.Manager
	httpChallenge bool

	readTimeout       time.Duration
	readHeaderTimeout time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration

	logger zerolog.Logger

	killChan chan struct{}
}

// WithHTTP allows you to create a server listener for HTTP connections.
// If New is also called with WithHTTPS or WithLetsEncrypt/WithLetsEncryptManager then this listener will
// function as a redirect listener and redirect traffic to HTTPS.
//
// If used with WithLetsEncrypt/WithLetsEncryptManager you must bind to :80 - as other ports are not supported.
func WithHTTP(bind string) Builder {
	return func(c *Config) error {
		if bind == "" {
			return errors.New("missing bind mandatory value in WithHTTP call")
		}

		c.httpBind = bind
		return nil
	}
}

// WithHTTPS allows you to create a server listener for HTTPS connections.
// If you want a custom TLS config, use WithTLS. Otherwise, WithHTTPS will use a sane default tls config.
func WithHTTPS(bind string, key string, cert string) Builder {
	return func(c *Config) error {
		if bind == "" {
			return errors.New("missing bind mandatory value in WithHTTPS call")
		}

		if key == "" {
			return errors.New("missing key mandatory value in WithHTTPS call")
		}

		if cert == "" {
			return errors.New("missing cert mandatory value in WithHTTPS call")
		}

		c.httpsBind = bind
		c.tlsKey = key
		c.tlsCert = cert
		c.tlsConfig = &tls.Config{
			// Causes servers to use Go's default ciphersuite preferences,
			// which are tuned to avoid attacks. Does nothing on clients.
			PreferServerCipherSuites: true,
			// Only use curves which have assembly implementations
			CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
			// Support http/2 and http/1.1
			NextProtos: []string{"h2", "http/1.1"},
		}

		return nil
	}
}

// WithTLS allows you to create a server listener for HTTPS connections with a custom TLS config.
// If you want a simple HTTPS listener using a sane default TLS config, use WithHTTPS.
func WithTLS(bind string, key string, cert string, config *tls.Config) Builder {
	return func(c *Config) error {
		if bind == "" {
			return errors.New("missing bind mandatory value in WithTLS call")
		}

		if key == "" {
			return errors.New("missing key mandatory value in WithTLS call")
		}

		if cert == "" {
			return errors.New("missing cert mandatory value in WithTLS call")
		}

		if config == nil {
			return errors.New("missing tls config mandatory value in WithTLS call")
		}

		c.httpsBind = bind
		c.tlsKey = key
		c.tlsCert = cert
		c.tlsConfig = config
		return nil
	}
}

// WithLetsEncrypt allows you to tell the server to use Let's Encrypt with auto-renewal for https certs.
// This version uses defaults for the autocert Manager & tls config. If you want more control, use WithLetsEncrypt.
// Bind is not configurable for let's encrypt and will always bind to :443.
//
// If httpChallenge is true, we will create a http -> https redirector that responds to let's encrypt HTTP challenges.
// This is required for Nginx, CloudFlare, and others because they do not support ALPN challenges.
// If you want to create a redirector that does not respond to HTTP challenges, and wish to use ALPN instead,
// you can use WithLetsEncrypt in conjunction with WithHTTP. Otherwise, you don't need to use WithHTTP.
func WithLetsEncrypt(httpChallenge bool, domains ...string) Builder {
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache("certs"),
	}

	return func(c *Config) error {
		if len(domains) == 0 {
			return errors.New("missing domains mandatory value in WithLetsEncrypt call")
		}

		if httpChallenge {
			c.httpBind = ":80"
		}
		c.httpsBind = ":443"
		c.letsEncryptManager = manager
		c.httpChallenge = httpChallenge

		c.tlsConfig = manager.TLSConfig()
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		c.tlsConfig.PreferServerCipherSuites = true
		// Only use curves which have assembly implementations
		c.tlsConfig.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.X25519}
		return nil
	}
}

// WithLetsEncryptManager allows you to tell the server to use Let's Encrypt with auto-renewal for https certs.
// If you'd like to use a default autocert Manager you can get one from NewBasicAutocertManager to provide here.
// If tls config is nil we will use a default tls config. If not-nil, the GetCertificate and NextProtos values will be
// replaced by values from the autocert manager's default TLS config, obtained via manager.TLSConfig().
// Bind is not configurable for let's encrypt and will always bind to :443.
//
// If httpChallenge is true, we will create a http -> https redirector that responds to let's encrypt HTTP challenges.
// This is required for Nginx, CloudFlare, and others because they do not support ALPN challenges.
// If you want to create a redirector that does not respond to HTTP challenges, and wish to use ALPN instead,
// you can use WithLetsEncryptManager in conjunction with WithHTTP. Otherwise, you don't need to use WithHTTP.
func WithLetsEncryptManager(manager *autocert.Manager, cfg *tls.Config, httpChallenge bool) Builder {
	if cfg == nil {
		cfg = manager.TLSConfig()
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		cfg.PreferServerCipherSuites = true
		// Only use curves which have assembly implementations
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.X25519}
	} else {
		c := manager.TLSConfig()
		// Set the mandatory lets encrypt tls config values.
		cfg.GetCertificate = c.GetCertificate
		cfg.NextProtos = c.NextProtos
	}

	return func(c *Config) error {
		if manager == nil {
			return errors.New("manager cannot be nil in WithLetsEncryptManager")
		}

		if manager.HostPolicy == nil {
			return errors.New("missing host policy in provided autocert manager in WithLetsEncrypt call")
		}

		if httpChallenge {
			c.httpBind = ":80"
		}
		c.httpsBind = ":443"
		c.letsEncryptManager = manager
		c.tlsConfig = cfg
		c.httpChallenge = httpChallenge
		return nil
	}
}

// WithTimeouts allows you to specify your own listener timeout values.
// Timeout docs can be found here: https://golang.org/pkg/net/http/
func WithTimeouts(read, readHeader, write, idle time.Duration) Builder {
	return func(c *Config) error {
		c.readTimeout = read
		c.readHeaderTimeout = readHeader
		c.writeTimeout = write
		c.idleTimeout = idle
		return nil
	}
}

// NewBasicAutocertManager creates a autocert manager with sane default values.
func NewBasicAutocertManager(domains ...string) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache("certs"),
	}
}

// New returns a new config to be supplied to Start to start the server.
// Writing to the returned kill chan will gracefully shutdown the server.
// Returns an error and a nil config if there are conflicting configuration entries.
//
// The most basic way to get started is:
// New(router, logger, servers.WithLetsEncrypt(true, "domain.com"))
// This creates a lets encrypt listener on :443, with a redirector on :80 that responds to let's encrypt http challenges.
//
// If WithHTTP is used alongside WithHTTPS/LetsEncrypt/TLS then the bind port (usually :80) will act as a
// redirector to the SSL port. You can also specify custom timeouts using WithTimeouts.
func New(router http.Handler, logger zerolog.Logger, builders ...Builder) (*Config, error) {
	killChan := make(chan struct{})

	cfg := &Config{
		router: router,

		readTimeout:       readTimeout,
		writeTimeout:      writeTimeout,
		idleTimeout:       0, // Uses readTimeout value.
		readHeaderTimeout: 0, // Uses readTimeout value.

		logger: logger,

		killChan: killChan,
	}

	for _, builder := range builders {
		if err := builder(cfg); err != nil {
			return nil, err
		}
	}

	if router == nil {
		return nil, errors.New("router cannot be nil")
	}

	if cfg.letsEncryptManager != nil && (cfg.tlsCert != "" || cfg.tlsKey != "") {
		return nil, errors.New("cannot use WithLetsEncrypt and WithHTTPS/WithTLS at the same time")
	}

	return cfg, nil
}

// Start a server with proper shutdown mechanics (os.Interrupt/Kill handlers).
// Use the New function with the "With" functions for setting up the Config to give to Start.
func (cfg *Config) Start() error {
	if cfg == nil {
		return errors.New("invalid config supplied to Start")
	}

	errs := make(chan error)

	// These start in goroutines and converge when we kill them
	primary := mainServer(cfg, errs)
	var secondary *http.Server

	if len(cfg.httpsBind) != 0 && len(cfg.httpBind) != 0 {
		secondary = redirectServer(cfg, errs)
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt, os.Kill)

	select {
	case <-cfg.killChan:
		cfg.logger.Info().Msg("internal shutdown initiated")
	case sig := <-quit:
		cfg.logger.Info().Str("signal", sig.String()).Msg("shutting down due to signal")
	case err := <-errs:
		cfg.logger.Error().Err(err).Msg("shutting down due to error")
	}

	if err := primary.Shutdown(context.Background()); err != nil {
		cfg.logger.Error().Err(err).Msg("error shutting down primary http(s) server")
	}
	if secondary != nil {
		if err := secondary.Shutdown(context.Background()); err != nil {
			cfg.logger.Error().Err(err).Msg("error shutting down redirecting http server")
		}
	}

	cfg.logger.Info().Msg("http(s) server shut down complete")
	return nil
}

// Stop uses the killChan to gracefully shutdown any active listeners.
func (cfg *Config) Stop() {
	cfg.killChan <- struct{}{}
}

func mainServer(cfg *Config, errs chan<- error) *http.Server {
	server := basicServer(cfg)
	server.Handler = cfg.router

	useTLS := len(cfg.httpsBind) != 0

	if !useTLS {
		server.Addr = cfg.httpBind

		cfg.logger.Info().Str("bind", cfg.httpBind).Msg("starting http listener")
		go func() {
			if err := server.ListenAndServe(); err != nil {
				errs <- errors.Wrap(err, "http listener died")
			}
		}()

		return server
	}

	server.Addr = cfg.httpsBind
	server.TLSConfig = cfg.tlsConfig
	cfg.logger.Info().Str("bind", cfg.httpBind).Msg("starting https listener")
	go func() {
		if err := server.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey); err != nil {
			errs <- errors.Wrap(err, "https listener died")
		}
	}()

	return server
}

func redirectServer(cfg *Config, errs chan<- error) *http.Server {
	_, httpsPort, err := net.SplitHostPort(cfg.httpsBind)
	if err != nil {
		errs <- errors.Wrap(err, "http listener died")
		return nil
	}

	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		httpHost := r.Host
		// Remove port if it exists so we can replace it with https port
		if strings.ContainsRune(r.Host, ':') {
			httpHost, _, err = net.SplitHostPort(r.Host)
			if err != nil {
				cfg.logger.Error().Err(err).Str("host", r.Host).Msg("failed to get http host from request")
				w.WriteHeader(http.StatusBadRequest)
				_, err = io.WriteString(w, "invalid host header")
				if err != nil {
					cfg.logger.Error().Err(err).Str("host", r.Host).Msg("failed to write to the response")
				}

				return
			}
		}

		var url string
		if httpsPort != "443" {
			url = fmt.Sprintf("https://%s:%s%s", httpHost, httpsPort, r.RequestURI)
		} else {
			url = fmt.Sprintf("https://%s%s", httpHost, r.RequestURI)
		}

		cfg.logger.Info().Str("remote", r.RemoteAddr).Str("host", r.Host).Str("path", r.URL.String()).Str("url", url).Msg("redirect")
		http.Redirect(w, r, url, http.StatusMovedPermanently)
	})

	server := basicServer(cfg)
	server.Addr = cfg.httpBind
	if cfg.httpChallenge {
		server.Handler = cfg.letsEncryptManager.HTTPHandler(redirectHandler)
	} else {
		server.Handler = redirectHandler
	}

	cfg.logger.Info().Str("bind", cfg.httpBind).Msg("starting http listener")
	go func() {
		if err := server.ListenAndServe(); err != nil {
			errs <- errors.Wrap(err, "http listener died")
		}
	}()

	return server
}

func basicServer(cfg *Config) *http.Server {
	server := &http.Server{
		ReadTimeout:       cfg.readTimeout,
		WriteTimeout:      cfg.writeTimeout,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		IdleTimeout:       cfg.idleTimeout,
		ErrorLog:          log.New(serverErrLogger{logger: cfg.logger}, "", 0),
	}

	return server
}
