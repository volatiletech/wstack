package mwares

import (
	"fmt"
	"net/http"

	"github.com/friendsofgo/errors"
	chimiddleware "github.com/go-chi/chi/middleware"
	"github.com/rs/zerolog"
)

// ZerologRecover will attempt to log a panic, as well as produce a reasonable
// error for the client by calling the passed in errorHandler function.
// If your app is using request-id logging, don't forget to write the request-id
// header in your errorHandler function as X-Request-ID. Or use the
// BasicPanicRecoverHandler if you want to have that done for you, and
// simply want to return a StatusInternalServerError on panics.
//
// It uses the zerolog logger and attempts to look up a request-scoped logger
// created with this package before using the passed in logger.
//
// The zerolog logger that's used here needs to have stacktrace logging enabled
// by setting zerolog.ErrorStackMarshaler, if using this middleware.
func ZerologRecover(fallback zerolog.Logger, errorHandler http.HandlerFunc) MW {
	return zerologRecoverMiddleware{
		fallback: fallback,
		eh:       errorHandler,
	}
}

// BasicPanicRecoverHandler is a basic panic recovery handler that will
// add the X-Request-ID header if present in the context, and return
// a http.StatusInternalServerError.
//
// This can be used as the errorHandler argument for ZerologRecover.
func BasicPanicRecoverHandler(w http.ResponseWriter, r *http.Request) {
	requestID := chimiddleware.GetReqID(r.Context())
	if len(requestID) > 0 {
		w.Header().Add("X-Request-ID", requestID)
	}
	w.WriteHeader(http.StatusInternalServerError)
}

type zerologRecoverMiddleware struct {
	fallback zerolog.Logger
	eh       http.HandlerFunc
}

func (z zerologRecoverMiddleware) Wrap(next http.Handler) http.Handler {
	return zerologRecoverer{
		zr:   z,
		next: next,
	}
}

type zerologRecoverer struct {
	zr   zerologRecoverMiddleware
	next http.Handler
}

func (z zerologRecoverer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer z.recoverNicely(w, r)
	z.next.ServeHTTP(w, r)
}

func (z zerologRecoverer) recoverNicely(w http.ResponseWriter, r *http.Request) {
	err := recover()
	if err == nil {
		return
	}

	var protocol string
	if r.TLS == nil {
		protocol = "http"
	} else {
		protocol = "https"
	}

	if z.zr.eh != nil {
		z.zr.eh(w, r)
	}

	logger := z.zr.fallback
	v := r.Context().Value(CTXKeyLogger)
	if v != nil {
		var ok bool
		logger, ok = v.(zerolog.Logger)
		if !ok {
			panic("cannot get derived request id logger from context object")
		}
	}

	logger.Error().Stack().
		Err(errors.New(fmt.Sprintf("%+v", err))).
		Str("method", r.Method).
		Str("uri", r.RequestURI).
		Str("protocol", r.Proto).
		Bool("tls", r.TLS != nil).
		Str("host", r.Host).
		Str("remote_addr", r.RemoteAddr).Msg(fmt.Sprintf("%s panic", protocol))
}
