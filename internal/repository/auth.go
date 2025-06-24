// Package repository provides persistence implementations for authentication services.
package repository

import (
	"context"
	"database/sql"
)

// PostgresAuthService implements authentication operations using a PostgreSQL database.
type PostgresAuthService struct {
	// DB is the database handle for executing queries.
	DB *sql.DB
}

// NewPostgresAuthService creates a new PostgresAuthService with the given database connection.
// db must be a valid *sql.DB connected to a PostgreSQL instance.
func NewPostgresAuthService(db *sql.DB) *PostgresAuthService {
	return &PostgresAuthService{DB: db}
}

// UserExists checks whether a user with the specified login exists in the database.
// It returns true if the user exists, false otherwise.
// If an error occurs during the query, it is returned.
func (s *PostgresAuthService) UserExists(ctx context.Context, login string) (bool, error) {
	var exists bool
	err := s.DB.QueryRowContext(
		ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE login = $1)`,
		login,
	).Scan(&exists)
	return exists, err
}

// RegisterUser attempts to register a new user with the given login.
// If a user with the same login already exists, the ON CONFLICT DO NOTHING clause prevents an error.
// Returns any error encountered while executing the insertion.
func (s *PostgresAuthService) RegisterUser(ctx context.Context, login string) error {
	_, err := s.DB.ExecContext(
		ctx,
		`INSERT INTO users (login) VALUES ($1) ON CONFLICT DO NOTHING`,
		login,
	)
	return err
}
