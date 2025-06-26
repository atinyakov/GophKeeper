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

// PostgresSyncService implements secret synchronization operations against a PostgreSQL database.
type PostgresSyncService struct {
	// DB is the database handle for executing queries and transactions.
	DB *sql.DB
}

// NewPostgresSyncService creates a new PostgresSyncService using the provided *sql.DB.
// db must be a valid connection to a PostgreSQL instance.
func NewPostgresSyncService(db *sql.DB) *PostgresSyncService {
	return &PostgresSyncService{DB: db}
}

// Sync synchronizes secrets for a given user. It compares the client's lastKnownVersion
// to the current maximum version in the database. If the client's version is behind,
// it returns all up-to-date secrets and the current version. Otherwise, it applies the
// provided secrets (inserting or updating each) and returns the client's version and
// the applied secrets. All operations occur within a single transaction.
//
//	ctx:        context for cancellation and deadlines
//	userID:     identifier of the user whose secrets are synchronized
//	secrets:    slice of models.Secret representing client changes
//	lastKnownVersion: client's last known sync version
//
// Returns a map with keys "version" (int64) and "secrets" ([]models.Secret), or an error.
func (s *PostgresSyncService) Sync(ctx context.Context, userID string, secrets []models.Secret, lastKnownVersion int64) (map[string]any, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Получить текущую максимальную версию
	var currentVersion int64
	err = tx.QueryRowContext(ctx, `
        SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_login = $1
    `, userID).Scan(&currentVersion)
	if err != nil {
		return nil, err
	}

	// Если версия клиента отстаёт — вернуть актуальные данные
	if lastKnownVersion < currentVersion {
		rows, err := tx.QueryContext(ctx, `
            SELECT id, type, data, comment, version FROM secrets WHERE user_login = $1
        `, userID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		var all []models.Secret
		for rows.Next() {
			var s models.Secret
			if err := rows.Scan(&s.ID, &s.Type, &s.Data, &s.Comment, &s.Version); err != nil {
				return nil, err
			}
			all = append(all, s)
		}

		return map[string]any{
			"version": currentVersion,
			"secrets": all,
		}, nil
	}

	// Иначе — применяем изменения
	for _, secret := range secrets {
		_, err := tx.ExecContext(ctx, `
            INSERT INTO secrets (id, user_login, type, data, comment, version)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                type = EXCLUDED.type,
                data = EXCLUDED.data,
                comment = EXCLUDED.comment,
                version = EXCLUDED.version
        `, secret.ID, userID, secret.Type, secret.Data, secret.Comment, secret.Version)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return map[string]any{
		"version": lastKnownVersion,
		"secrets": secrets,
	}, nil
}

// GetMaxVersion retrieves the highest version number of all secrets belonging to the given user.
// If no secrets exist, it returns 0.
//
//	ctx:    context for cancellation and deadlines
//	userID: identifier of the user
//
// Returns the maximum version (int64) or an error if the query fails.
func (s *PostgresSyncService) GetMaxVersion(ctx context.Context, userID string) (int64, error) {
	var version int64
	err := s.DB.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_login = $1
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
func (s *PostgresSyncService) GetSecretsByUser(ctx context.Context, userID string) ([]models.Secret, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, type, data, comment, version FROM secrets WHERE user_login = $1
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("GetSecretsByUser: %w", err)
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var s models.Secret
		if err := rows.Scan(&s.ID, &s.Type, &s.Data, &s.Comment, &s.Version); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		secrets = append(secrets, s)
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
func (s *PostgresSyncService) UpsertSecrets(ctx context.Context, userID string, secrets []models.Secret) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, s := range secrets {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO secrets (id, user_login, type, data, comment, version)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (id) DO UPDATE SET
				type = EXCLUDED.type,
				data = EXCLUDED.data,
				comment = EXCLUDED.comment,
				version = EXCLUDED.version
		`, s.ID, userID, s.Type, s.Data, s.Comment, s.Version)
		if err != nil {
			return fmt.Errorf("upsert: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// DeleteSecrets removes secrets by their IDs for the specified user.
//
//	ctx:    context for cancellation and deadlines
//	userID:  identifier of the user
//	ids:     slice of secret IDs to delete
//
// Returns an error if the delete operation fails.
func (s *PostgresSyncService) DeleteSecrets(ctx context.Context, userID string, ids []string) error {
	query := `DELETE FROM secrets WHERE user_login = $1 AND id = ANY($2)`
	// pq.Array turns []string into a driver.Valuer that marshals into TEXT[]
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
func (s *PostgresSyncService) GetSecretByID(ctx context.Context, userID string, id string) (*models.Secret, error) {
	var secret models.Secret
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, type, data, comment, version FROM secrets
		WHERE user_login = $1 AND id = $2
	`, userID, id).Scan(&secret.ID, &secret.Type, &secret.Data, &secret.Comment, &secret.Version)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}
