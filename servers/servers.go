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

// ServerErrLogger allows us to use the zap.logger as our http.Server ErrorLog
type ServerErrLogger struct {
	logger *zerolog.Logger
}

// Implement Write to log server errors using the zerolog logger
func (s ServerErrLogger) Write(b []byte) (int, error) {
	s.logger.Error().Str("error", string(b)).Msg("server error")
	return 0, nil
}

type ConfigBuilder func(*Config) error

type Config struct {
	router http.Handler

	httpBind string

	httpsBind string
	tlsKey    string
	tlsCert   string
	tlsConfig *tls.Config

	letsEncryptManager *autocert.Manager

	readTimeout       time.Duration
	readHeaderTimeout time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration

	logger *zerolog.Logger

	killChan chan struct{}
}

// WithHTTP allows you to create a server listener for HTTP connections.
// If New is also called with WithHTTPS or WithLetsEncrypt/WithLetsEncryptBasic then this listener will
// function as a redirect listener and redirect traffic to HTTPS.
func WithHTTP(bind string) ConfigBuilder {
	return func(c *Config) error {
		if bind == "" {
			return errors.New("missing mandatory values in WithHTTP call")
		}

		c.httpBind = bind
		return nil
	}
}

// WithHTTPS allows you to create a server listener for HTTPS connections.
// If you want a custom TLS config, use WithTLS. Otherwise, WithHTTPS will use a sane default tls config.
func WithHTTPS(bind string, key string, cert string) ConfigBuilder {
	return func(c *Config) error {
		if bind == "" || key == "" || cert == "" {
			return errors.New("missing mandatory values in WithHTTPS call")
		}

		c.httpsBind = bind
		c.tlsKey = key
		c.tlsCert = cert
		return nil
	}
}

// WithTLS allows you to create a server listener for HTTPS connections with a custom TLS config.
// If you want a simple HTTPS listener using a sane default TLS config, use WithHTTPS.
func WithTLS(bind string, key string, cert string, config *tls.Config) ConfigBuilder {
	return func(c *Config) error {
		if bind == "" || key == "" || cert == "" || config == nil {
			return errors.New("missing mandatory values in WithHTTPS call")
		}

		c.httpsBind = bind
		c.tlsKey = key
		c.tlsCert = cert
		c.tlsConfig = config
		return nil
	}
}

// WithLetsEncryptBasic allows you to tell the server to use Let's Encrypt with auto-renewal for https certs.
// The Basic version uses sane defaults for the autocert Manager. If you want more control, use WithLetsEncrypt.
func WithLetsEncryptBasic(bind string, domains ...string) ConfigBuilder {
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache("certs"),
	}

	return func(c *Config) error {
		if bind == "" || len(domains) == 0 {
			return errors.New("missing mandatory values in WithLetsEncryptBasic call")
		}

		c.httpsBind = bind
		c.letsEncryptManager = manager
		return nil
	}
}

// WithLetsEncrypt allows you to tell the server to use Let's Encrypt with auto-renewal for https certs.
func WithLetsEncrypt(bind string, manager autocert.Manager) ConfigBuilder {
	return func(c *Config) error {
		if bind == "" {
			return errors.New("missing mandatory values in WithLetsEncrypt call")
		}

		c.httpsBind = bind
		c.letsEncryptManager = &manager
		return nil
	}
}

// WithTimeouts allows you to specify your own listener timeout values.
// Timeout docs can be found here: https://golang.org/pkg/net/http/
func WithTimeouts(read, readHeader, write, idle time.Duration) ConfigBuilder {
	return func(c *Config) error {
		c.readTimeout = read
		c.readHeaderTimeout = readHeader
		c.writeTimeout = write
		c.idleTimeout = idle
		return nil
	}
}

// New returns a new config to be supplied to Start to start the server.
// Writing to the returned kill chan will gracefully shutdown the server.
// Returns an error and a nil config if there are conflicting configuration entries.
//
// The most basic way to get started is:
// New(router, servers.WithHTTP(":80"), servers.WithLetsEncryptBasic(":443", "domain.com"))
//
// If WithHTTP is used alongside WithHTTPS/LetsEncrypt/TLS then port 80 will act as a redirector to the SSL port.
// You can also specify custom timeouts using WithTimeouts.
func New(router http.Handler, logger *zerolog.Logger, builders ...ConfigBuilder) (*Config, chan struct{}, error) {
	killChan := make(chan struct{})

	cfg := &Config{
		router: router,

		readTimeout:       readTimeout,
		writeTimeout:      writeTimeout,
		idleTimeout:       0, // Uses readTimeout value.
		readHeaderTimeout: 0, // Uses readTimeout value.

		logger: logger,

		killChan: killChan,

		tlsConfig: &tls.Config{
			// Causes servers to use Go's default ciphersuite preferences,
			// which are tuned to avoid attacks. Does nothing on clients.
			PreferServerCipherSuites: true,
			// Only use curves which have assembly implementations
			CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
			// Support http/2 and http/1.1
			NextProtos: []string{"h2", "http/1.1"},
		},
	}

	for _, builder := range builders {
		if err := builder(cfg); err != nil {
			return nil, nil, err
		}
	}

	if router == nil {
		return nil, nil, errors.New("router cannot be nil")
	}

	if logger == nil {
		return nil, nil, errors.New("logger cannot be nil")
	}

	if cfg.letsEncryptManager != nil && (cfg.tlsCert != "" || cfg.tlsKey != "") {
		return nil, nil, errors.New("cannot use WithLetsEncrypt and WithHTTPS/WithTLS at the same time")
	}

	return cfg, killChan, nil
}

// Start a server with proper shutdown mechanics (os.Interrupt/Kill handlers).
// Use the New function with the "With" functions for setting up the Config to give to Start.
func Start(cfg *Config) error {
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

	server := basicServer(cfg)
	server.Addr = cfg.httpBind
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		ErrorLog:          log.New(ServerErrLogger{logger: cfg.logger}, "", 0),
	}

	return server
}
