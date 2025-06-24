// Package http provides HTTP routing and middleware configuration
// for the GophKeeper service.
package http

import (
	"net/http"

	"github.com/atinyakov/GophKeeper/internal/middleware"
	"go.uber.org/zap"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
)

// NewRouter constructs and returns an HTTP handler that serves
// the GophKeeper API. It applies JSON content-type enforcement,
// request logging, and certificate-based authentication, and
// mounts the registration, login, and sync endpoints under /api.
//
// Parameters:
//
//	authHandler  - handler for registration and login endpoints
//	syncHandler  - handler for secret synchronization endpoint
//	logger       - structured logger for request logging middleware
//
// Routes:
//
//	POST /api/register   → authHandler.Register
//	POST /api/login      → authHandler.Login
//	POST /api/sync       → syncHandler.Sync (protected by CertAuth)
//
// Middleware chain (applied in order):
//  1. AllowContentType("application/json") — rejects non-JSON requests
//  2. WithRequestLogging(logger)         — logs incoming requests
//  3. CertAuth                          — enforces TLS client certificate auth
func NewRouter(
	authHandler *AuthHandler,
	syncHandler *SyncHandler,
	logger *zap.Logger,
) http.Handler {
	r := chi.NewRouter()

	// Only allow requests with Content-Type: application/json
	r.Use(chiMiddleware.AllowContentType("application/json"))

	// Log each request and its metadata
	r.Use(middleware.WithRequestLogging(logger))
	// Enforce certificate-based authentication
	r.Use(middleware.CertAuth)

	// Mount API routes
	r.Route("/api", func(r chi.Router) {
		// Public endpoints
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)

		// Protected group: requires valid client certificate
		r.Group(func(r chi.Router) {
			r.Post("/sync", syncHandler.Sync)
		})
	})

	return r
}
