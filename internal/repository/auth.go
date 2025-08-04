// Package repository provides persistence implementations for authentication services.
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

// PostgresAuthRepository implements authentication operations using a PostgreSQL database.
type PostgresAuthRepository struct {
	// DB is the database handle for executing queries.
	DB *sql.DB
}

// NewPostgresAuthRepository creates a new PostgresAuthService with the given database connection.
// db must be a valid *sql.DB connected to a PostgreSQL instance.
func NewPostgresAuthRepository(db *sql.DB) *PostgresAuthRepository {
	return &PostgresAuthRepository{DB: db}
}

// UserExists checks whether a user with the specified login exists in the database.
// It returns true if the user exists, false otherwise.
// If an error occurs during the query, it is returned.
func (s *PostgresAuthRepository) UserExists(ctx context.Context, login string) (bool, error) {
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
func (s *PostgresAuthRepository) RegisterUser(ctx context.Context, login string) error {
	_, err := s.DB.ExecContext(
		ctx,
		`INSERT INTO users (login) VALUES ($1)`,
		login,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			// duplicate key – пользователь уже есть
			return nil
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}
