// Package middleware provides HTTP middlewares for authentication and logging.
package middleware

import (
	"context"
	"net/http"
)

type ctxKey string

const userKey ctxKey = "user"

// CertAuth is a middleware that enforces mutual TLS authentication.
//
// It checks whether the incoming HTTP request has a valid client certificate.
// The /api/register endpoint is excluded from certificate validation to allow
// new users to register and obtain a certificate.
//
// On successful validation, it extracts the Common Name (CN) from the client's
// certificate and stores it in the request context, so it can be used
// downstream as the authenticated user ID.
func CertAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/register" {
			// Allow registration without certificate
			next.ServeHTTP(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client certificate provided", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		ctx := context.WithValue(r.Context(), userKey, cert.Subject.CommonName)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserIDFromContext extracts the user ID (Common Name from client certificate)
// from the request context. Returns an empty string if not found.
func GetUserIDFromContext(ctx context.Context) string {
	val := ctx.Value(userKey)
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}
