package mwares

import (
"bufio"
"fmt"
"net"
"net/http"
"time"

"github.com/friendsofgo/errors"
"github.com/rs/zerolog"
)

// MW is an interface defining middleware wrapping
type MW interface {
	Wrap(http.Handler) http.Handler
}

type zerologMiddleware struct {
	logger zerolog.Logger
}

// Zerolog returns a logging middleware that outputs details about a request
func Zerolog(logger zerolog.Logger) MW {
	return zerologMiddleware{logger: logger}
}

// Wrap middleware handles web request logging using Zerolog
func (z zerologMiddleware) Wrap(next http.Handler) http.Handler {
	return zerologger{mid: z, next: next}
}

type zerologger struct {
	mid  zerologMiddleware
	next http.Handler
}

// zerologResponseWriter is a wrapper that includes that http status and size for logging
type zerologResponseWriter struct {
	http.ResponseWriter
	status   int
	size     int
	hijacked bool
}

func (z zerologger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	zw := &zerologResponseWriter{ResponseWriter: w}

	// Serve the request
	z.next.ServeHTTP(zw, r)

	// Write the request log line
	z.write(zw, r, startTime)
}

func (z zerologger) write(zw *zerologResponseWriter, r *http.Request, startTime time.Time) {
	elapsed := time.Now().Sub(startTime)
	var protocol string
	if r.TLS == nil {
		protocol = "http"
	} else {
		protocol = "https"
	}

	logger := z.mid.logger
	subLogger := logger.With().
		Int("status", zw.status).
		Int("size", zw.size).
		Bool("hijacked", zw.hijacked).
		Int("status", zw.status).
		Int("size", zw.size).
		Bool("hijacked", zw.hijacked).
		Str("method", r.Method).
		Str("uri", r.RequestURI).
		Bool("tls", r.TLS != nil).
		Str("protocol", r.Proto).
		Str("host", r.Host).
		Str("remote_addr", r.RemoteAddr).
		Dur("elapsed", elapsed).
		Logger()

	if ff := r.Header.Get("X-Forwarded-For"); ff != "" {
		subLogger = subLogger.With().Str("x_forwarded_for", ff).Logger()
	}

	subLogger.Debug().Msg(fmt.Sprintf("%s request", protocol))
}

func (z *zerologResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := z.ResponseWriter.(http.Hijacker); ok {
		z.hijacked = true
		return hijacker.Hijack()
	}
	return nil, nil, errors.Errorf("%T does not support http hijacking", z.ResponseWriter)
}

func (z *zerologResponseWriter) WriteHeader(code int) {
	z.status = code
	z.ResponseWriter.WriteHeader(code)
}

func (z *zerologResponseWriter) Write(b []byte) (int, error) {
	size, err := z.ResponseWriter.Write(b)
	z.size += size
	return size, err
}
