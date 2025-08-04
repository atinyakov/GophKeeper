// Package repository provides persistence implementations for synchronization services
// using a PostgreSQL database.
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/atinyakov/GophKeeper/internal/models"
	"github.com/lib/pq"
)

// PostgresSyncRepository implements secret synchronization operations against a PostgreSQL database.
type PostgresSyncRepository struct {
	// DB is the database handle for executing queries and transactions.
	DB *sql.DB
}

// NewPostgresSyncRepostitory creates a new PostgresSyncService using the provided *sql.DB.
// db must be a valid connection to a PostgreSQL instance.
func NewPostgresSyncRepostitory(db *sql.DB) *PostgresSyncRepository {
	return &PostgresSyncRepository{DB: db}
}

// GetMaxVersion retrieves the highest version number of all secrets belonging to the given user.
// If no secrets exist, it returns 0.
//
//	ctx:    context for cancellation and deadlines
//	userID: identifier of the user
//
// Returns the maximum version (int64) or an error if the query fails.
func (s *PostgresSyncRepository) GetMaxVersion(ctx context.Context, userID string) (int64, error) {
	var version int64
	err := s.DB.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_login = $1 AND deleted = false
	`, userID).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("GetMaxVersion failed: %w", err)
	}
	return version, nil
}

// GetSecretsByUser fetches all secrets for the specified user.
//
//	ctx:    context for cancellation and deadlines
//	userID: identifier of the user
//
// Returns a slice of models.Secret or an error if the query or scanning fails.
func (s *PostgresSyncRepository) GetSecretsByUser(ctx context.Context, userID string) ([]models.Secret, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, type, data, comment, version, deleted FROM secrets WHERE user_login = $1 AND deleted = false
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("GetSecretsByUser: %w", err)
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var sec models.Secret
		if err := rows.Scan(&sec.ID, &sec.Type, &sec.Data, &sec.Comment, &sec.Version, &sec.Deleted); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		secrets = append(secrets, sec)
	}
	return secrets, nil
}

// UpsertSecrets inserts or updates multiple secrets for a given user within a transaction.
// Each secret is inserted if new, or updated on conflict by ID.
//
//	ctx:    context for cancellation and deadlines
//	userID: identifier of the user
//	secrets: slice of models.Secret to upsert
//
// Returns an error if any operation or transaction fails.
// func (s *PostgresSyncRepository) UpsertSecrets(ctx context.Context, userID string, secrets []models.Secret) error {
// 	tx, err := s.DB.BeginTx(ctx, nil)
// 	if err != nil {
// 		return fmt.Errorf("begin tx: %w", err)
// 	}
// 	defer tx.Rollback()

// 	for _, sec := range secrets {
// 		_, err := tx.ExecContext(ctx, `
// 			INSERT INTO secrets (id, user_login, type, data, comment, version, deleted)
// 			VALUES ($1, $2, $3, $4, $5, $6, false)
// 			ON CONFLICT (id) DO UPDATE SET
// 				type = EXCLUDED.type,
// 				data = EXCLUDED.data,
// 				comment = EXCLUDED.comment,
// 				version = EXCLUDED.version,
// 				deleted = false
// 		`, sec.ID, userID, sec.Type, sec.Data, sec.Comment, sec.Version)
// 		if err != nil {
// 			return fmt.Errorf("upsert: %w", err)
// 		}
// 	}

// 	if err := tx.Commit(); err != nil {
// 		return fmt.Errorf("commit: %w", err)
// 	}
// 	return nil
// }

// DeleteSecrets removes secrets by their IDs for the specified user.
//
//	ctx:    context for cancellation and deadlines
//	userID:  identifier of the user
//	ids:     slice of secret IDs to delete
//
// Returns an error if the delete operation fails.
func (s *PostgresSyncRepository) DeleteSecrets(ctx context.Context, userID string, ids []string) error {
	query := `UPDATE secrets SET deleted = true WHERE user_login = $1 AND id = ANY($2)`
	_, err := s.DB.ExecContext(ctx, query, userID, pq.Array(ids))
	return err
}

// GetSecretByID retrieves a single secret by ID for the given user.
//
//	ctx:    context for cancellation and deadlines
//	userID: identifier of the user
//	id:     ID of the secret to fetch
//
// Returns a pointer to models.Secret or an error if not found or on failure.
func (s *PostgresSyncRepository) GetSecretByID(ctx context.Context, userID string, id string) (*models.Secret, error) {
	var secret models.Secret
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, type, data, comment, version, deleted FROM secrets
		WHERE user_login = $1 AND id = $2 AND deleted = false
	`, userID, id).Scan(&secret.ID, &secret.Type, &secret.Data, &secret.Comment, &secret.Version, &secret.Deleted)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// UpsertIfNewer updates only those secrets which have a higher version.
func (s *PostgresSyncRepository) UpsertIfNewer(ctx context.Context, userID string, secrets []models.Secret) ([]string, []string, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	updated := make([]string, 0, len(secrets))
	skipped := make([]string, 0, len(secrets))

	for _, sec := range secrets {
		var existingVersion int64
		err := tx.QueryRowContext(ctx, `
			SELECT version FROM secrets WHERE id = $1 AND user_login = $2 AND deleted = false
		`, sec.ID, userID).Scan(&existingVersion)
		if err != nil && err != sql.ErrNoRows {
			return nil, nil, fmt.Errorf("check version: %w", err)
		}
		if err == nil && existingVersion >= sec.Version {
			skipped = append(skipped, sec.ID)
			continue
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO secrets (id, user_login, type, data, comment, version, deleted)
			VALUES ($1, $2, $3, $4, $5, $6, false)
			ON CONFLICT (id) DO UPDATE SET
				type = EXCLUDED.type,
				data = EXCLUDED.data,
				comment = EXCLUDED.comment,
				version = EXCLUDED.version,
				deleted = false
		`, sec.ID, userID, sec.Type, sec.Data, sec.Comment, sec.Version)
		if err != nil {
			return nil, nil, fmt.Errorf("upsert: %w", err)
		}
		updated = append(updated, sec.ID)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit: %w", err)
	}
	return updated, skipped, nil
}

// GetNewerSecrets returns all secrets with versions newer than those the client knows.
func (s *PostgresSyncRepository) GetNewerSecrets(ctx context.Context, userID string, versions map[string]int64) ([]models.Secret, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, type, data, comment, version, deleted FROM secrets WHERE user_login = $1 AND deleted = false
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("GetNewerSecrets: %w", err)
	}
	defer rows.Close()

	var newer []models.Secret
	for rows.Next() {
		var sec models.Secret
		if err := rows.Scan(&sec.ID, &sec.Type, &sec.Data, &sec.Comment, &sec.Version, &sec.Deleted); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if clientVer, ok := versions[sec.ID]; !ok || sec.Version > clientVer {
			newer = append(newer, sec)
		}
	}
	return newer, nil
}
