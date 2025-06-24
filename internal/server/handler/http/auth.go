// Package http provides HTTP handlers for user authentication,
// including registration and certificate-based login.
package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/atinyakov/GophKeeper/internal/certgen"
)

// AuthService defines the interface for authentication operations
// required by the HTTP handlers.
type AuthService interface {
	// UserExists checks whether a user with the given login exists.
	// Returns true if the user exists, false otherwise.
	UserExists(context.Context, string) (bool, error)
	// RegisterUser registers a new user with the given login.
	RegisterUser(context.Context, string) error
}

// AuthHandler handles HTTP requests for user registration and login.
type AuthHandler struct {
	// AuthService performs the underlying authentication operations.
	AuthService AuthService
}

// RegisterRequest represents the JSON payload for user registration.
type RegisterRequest struct {
	// Login is the username to register.
	Login string `json:"login"`
}

// Register handles user registration requests.
// It expects a JSON body with a non-empty "login" field.
// If the user does not already exist, it registers the user,
// generates a client certificate signed by the CA, stores
// the user in the database, and returns the PEM-encoded
// certificate and private key.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Login == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	exists, err := h.AuthService.UserExists(r.Context(), req.Login)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}

	// Load CA credentials for signing
	caCert, caKey, err := certgen.LoadCACredentials("certs/ca.crt", "certs/ca.key")
	if err != nil {
		http.Error(w, "failed to load CA", http.StatusInternalServerError)
		return
	}

	// Generate user certificate signed by the CA
	certPEM, keyPEM, err := certgen.GenerateUserCertificate(req.Login, caCert, caKey)
	if err != nil {
		http.Error(w, "failed to generate certificate", http.StatusInternalServerError)
		return
	}

	// Save the new user in the database
	if err := h.AuthService.RegisterUser(r.Context(), req.Login); err != nil {
		http.Error(w, "failed to save user", http.StatusInternalServerError)
		return
	}

	// Respond with the generated certificate and key
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cert": string(certPEM),
		"key":  string(keyPEM),
	})
}

// Login handles certificate-based login requests.
// It expects the client to present a valid TLS certificate.
// The CommonName from the client certificate is used as the login.
// If the user exists, it returns a JSON status "ok" and the username.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}

	cert := r.TLS.PeerCertificates[0]
	login := cert.Subject.CommonName

	exists, err := h.AuthService.UserExists(r.Context(), login)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "user not found", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"user":   login,
	})
}
