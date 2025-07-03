// Package service provides business-logic services for authentication and secret synchronization,
// delegating persistence to repository interfaces.
package service

import (
	"context"

	"github.com/atinyakov/GophKeeper/internal/models"
)

// SyncRepository defines the persistence operations needed by the SyncService.
type SyncRepository interface {
	// GetMaxVersion returns the highest version number of secrets for the given user.
	// If no secrets exist, it should return 0.
	GetMaxVersion(ctx context.Context, userID string) (int64, error)
	// GetSecretsByUser retrieves all secrets belonging to the specified user.
	GetSecretsByUser(ctx context.Context, userID string) ([]models.Secret, error)
	// UpsertSecrets inserts new secrets or updates existing ones for the given user.
	// UpsertSecrets(ctx context.Context, userID string, secrets []models.Secret) error
	// DeleteSecrets removes the secrets with the given IDs for the specified user.
	DeleteSecrets(ctx context.Context, userID string, ids []string) error
	// GetSecretByID fetches a single secret by ID for the specified user.
	GetSecretByID(ctx context.Context, userID string, id string) (*models.Secret, error)
	// UpsertIfNewer
	UpsertIfNewer(ctx context.Context, userID string, secrets []models.Secret) ([]string, []string, error)
	// GetNewerSecrets
	GetNewerSecrets(ctx context.Context, userID string, versions map[string]int64) ([]models.Secret, error)
}

// SyncService implements synchronization business logic for user secrets.
type SyncService struct {
	// repo is the underlying persistence repository.
	repo SyncRepository
}

// NewSyncService constructs a SyncService with the provided SyncRepository.
// repo must implement all required methods for synchronization.
func NewSyncService(repo SyncRepository) *SyncService {
	return &SyncService{repo: repo}
}

// Sync synchronizes client-provided secrets with the data store.
// For each secret, the server compares versions and updates only if the incoming version is newer.
// Deleted secrets are removed; version conflicts are resolved by keeping the higher version.
func (s *SyncService) Sync(ctx context.Context, userID string, secrets []models.Secret, clientVersions map[string]int64) (map[string]any, error) {
	var toUpsert []models.Secret
	var toDelete []string
	for _, s := range secrets {
		if s.Deleted {
			toDelete = append(toDelete, s.ID)
		} else {
			toUpsert = append(toUpsert, s)
		}
	}

	if len(toDelete) > 0 {
		if err := s.repo.DeleteSecrets(ctx, userID, toDelete); err != nil {
			return nil, err
		}
	}

	var updated, skipped []string
	if len(toUpsert) > 0 {
		var err error
		updated, skipped, err = s.repo.UpsertIfNewer(ctx, userID, toUpsert)
		if err != nil {
			return nil, err
		}
	}

	newerSecrets, err := s.repo.GetNewerSecrets(ctx, userID, clientVersions)
	if err != nil {
		return nil, err
	}

	version, err := s.repo.GetMaxVersion(ctx, userID)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"version": version,
		"updated": updated,
		"skipped": skipped,
		"secrets": newerSecrets,
	}, nil
}

// Delete removes the specified secrets for the user from the data store.
func (s *SyncService) Delete(ctx context.Context, userID string, ids []string) error {
	return s.repo.DeleteSecrets(ctx, userID, ids)
}

// GetByID retrieves a single secret by its ID for the given user.
func (s *SyncService) GetByID(ctx context.Context, userID string, id string) (*models.Secret, error) {
	return s.repo.GetSecretByID(ctx, userID, id)
}
