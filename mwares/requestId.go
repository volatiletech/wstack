package mwares

import (
	"context"
	"net/http"

	chimiddleware "github.com/go-chi/chi/middleware"
	"github.com/rs/zerolog"
)

type ctxKey int

const (
	// CTXKeyLogger is the key under which the request scoped logger is placed
	CTXKeyLogger ctxKey = iota
)

// ZerologRequestIDLogger returns a request id logger middleware. This only works
// if chi has inserted a request id into the stack first.
func ZerologRequestIDLogger(logger zerolog.Logger) MW {
	return zerologReqLoggerMiddleware{logger: logger}
}

type zerologReqLoggerMiddleware struct {
	logger zerolog.Logger
}

func (z zerologReqLoggerMiddleware) Wrap(next http.Handler) http.Handler {
	return zerologReqLoggerInserter{logger: z.logger, next: next}
}

type zerologReqLoggerInserter struct {
	logger zerolog.Logger
	next   http.Handler
}

func (z zerologReqLoggerInserter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := chimiddleware.GetReqID(r.Context())
	derivedLogger := z.logger.With().Str("request_id", requestID)

	r = r.WithContext(context.WithValue(r.Context(), CTXKeyLogger, derivedLogger))
	z.next.ServeHTTP(w, r)
}

// Logger returns the Request ID scoped logger from the request Context
// and panics if it cannot be found. This function is only ever used
// by your controllers if your app uses the RequestID middlewares,
// otherwise you should use the controller's receiver logger directly.
func Logger(r *http.Request) *zerolog.Logger {
	return LoggerCTX(r.Context())
}

// LoggerCTX retrieves a logger from a context.
func LoggerCTX(ctx context.Context) *zerolog.Logger {
	v := ctx.Value(CTXKeyLogger)
	log, ok := v.(*zerolog.Logger)
	if !ok {
		panic("cannot get derived request id logger from context object")
	}
	return log
}
