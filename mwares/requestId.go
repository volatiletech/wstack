package mwares

import (
	"net/http"

	chimiddleware "github.com/go-chi/chi/middleware"
	"github.com/rs/zerolog"
)

// ZerologRequestIDLogger returns a request id logger middleware. This only works
// if chi has inserted a request id into the stack first.
func ZerologRequestIDLogger(logger *zerolog.Logger) MW {
	return zerologReqLoggerMiddleware{logger: logger}
}

type zerologReqLoggerMiddleware struct {
	logger *zerolog.Logger
}

func (z zerologReqLoggerMiddleware) Wrap(next http.Handler) http.Handler {
	return zerologReqLoggerInserter{logger: *z.logger, next: next}
}

type zerologReqLoggerInserter struct {
	logger zerolog.Logger
	next   http.Handler
}

func (z zerologReqLoggerInserter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := chimiddleware.GetReqID(r.Context())
	derivedLogger := z.logger.With().Str("request_id", requestID).Logger()

	r = r.WithContext(derivedLogger.WithContext(r.Context()))

	z.next.ServeHTTP(w, r)
}