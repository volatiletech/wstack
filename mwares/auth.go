package mwares

import (
	"net/http"

	"github.com/friendsofgo/errors"
	"github.com/rs/zerolog"
)

// ErrUserNotFound should be returned from Get when the record is not found.
var ErrUserNotFound = errors.New("user not found")

// UserManagement is an interface that allows control over the AuthCheckMiddleware.
type UserManagement interface {
	IsAuthed(r *http.Request) (isAuthed bool)
	SetSessionOnContext(r **http.Request) (interface{}, error)
}

// AuthCheckMiddleware prevents someone from accessing a route that should
// be only allowed for users who are logged in. This middleware is designed
// to be used in client-side apps, because it does not handle redirecting.
//
// It allows the user through if the SessionKey is present in
// the session, and is valid and non-expired.
//
// UserManagement is an interface that implements context management to pass
// along the authed user state, whether that be a username or a simple bool
// to indicate that the requester is authed, or alternatively the implementation
// could just return nil, nil if there is no additional state to pass along.
// It also implements a function to check whether the supplied request holds
// details of an authed user. Usually this means your implementation would
// involve checking the request variable for an active and valid cookie.
//
// log is a zerolog logger that is used if a logger cannot be found in the request context.
// Generally AuthCheckMiddleware is used with the zerolog logging middlewares,
// and the zerolog request id middlewares, so the context key will match as a result.
func AuthCheckMiddleware(um UserManagement, log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//log := ab.RequestLogger(r)
			// get logger from context, if that fails, use supplied logger

			newLog := log.With().Str("path", r.URL.Path).Logger()

			if !um.IsAuthed(r) {
				newLog.Info().Msg("user unauthorized")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if _, err := um.SetSessionOnContext(&r); err == ErrUserNotFound {
				newLog.Info().Msg("user not found")
				w.WriteHeader(http.StatusUnauthorized)
				return
			} else if err != nil {
				log.Error().Err(err).Msg("error retrieving current user")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
