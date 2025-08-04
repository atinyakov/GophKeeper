// Package service provides authentication business logic,
// delegating persistence to an AuthRepository.
package service

import (
	"context"
)

// AuthRepository defines the persistence operations
// required by the authentication service.
type AuthRepository interface {
	// UserExists returns true if a user with the given login exists.
	// ctx carries deadlines, cancellation signals, and other request-scoped values.
	UserExists(ctx context.Context, login string) (bool, error)
	// RegisterUser creates a new user record with the given login.
	// Returns an error if the operation fails.
	RegisterUser(ctx context.Context, login string) error
}

// Service implements authentication operations by delegating
// to an AuthRepository.
type Service struct {
	// repo performs the data-layer operations.
	repo AuthRepository
}

// NewAuthService constructs a new Service using the provided repository.
// repo must implement AuthRepository.
func NewAuthService(repo AuthRepository) *Service {
	return &Service{repo: repo}
}

// UserExists checks whether a user with the specified login exists.
// It returns true if the user exists, false otherwise, along with any error.
func (s *Service) UserExists(ctx context.Context, login string) (bool, error) {
	return s.repo.UserExists(ctx, login)
}

// RegisterUser attempts to register a new user with the given login.
// Returns an error if the repository operation fails.
func (s *Service) RegisterUser(ctx context.Context, login string) error {
	return s.repo.RegisterUser(ctx, login)
}
