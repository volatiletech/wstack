package mwares

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aarondl/oa3/support"
	"github.com/rs/zerolog"
)

// NewUnexpectedErrorHandler is a validation error handler and http 500 error handler,
// primarily for use with oa3 generated APIs.
//
// oa3 API's take a validation error converter and a error handler on initialization.
// The returned object here can be used as the error handler argument,
// and the ValidationConverter function in this package can be used the validation converter argument.
func NewUnexpectedErrorHandler(log zerolog.Logger) UnexpectedErrorHandler {
	return UnexpectedErrorHandler{log: log}
}

type UnexpectedErrorHandler struct {
	log zerolog.Logger
}

func (e UnexpectedErrorHandler) Wrap(fn func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return errorHandle{h: fn, log: e.log}
}

type errorHandle struct {
	h   func(w http.ResponseWriter, r *http.Request) error
	log zerolog.Logger
}

// ServeHTTP processes the error returned from oa3 API's.
// If it's a validation error it will write it out as JSON and return StatusUnprocessableEntity.
// If it's a generic error it will be logged, and returned as a StatusInternalServerError.
func (e errorHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := e.h(w, r)
	if err == nil {
		return
	}

	if v, ok := err.(validationErr); ok {
		w.WriteHeader(http.StatusUnprocessableEntity)
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		if _, err = w.Write(b); err != nil {
			panic(err)
		}
		return
	}

	e.log.Error().Err(err).Msg("unexpected internal server error")
	w.WriteHeader(http.StatusInternalServerError)
}

type validationErr map[string][]string

func (v validationErr) Error() string {
	return fmt.Sprintf("%#v", map[string][]string(v))
}

func ValidationConverter(errs support.Errors) error {
	return validationErr(errs)
}
