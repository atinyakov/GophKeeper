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
	UpsertSecrets(ctx context.Context, userID string, secrets []models.Secret) error
	// DeleteSecrets removes the secrets with the given IDs for the specified user.
	DeleteSecrets(ctx context.Context, userID string, ids []string) error
	// GetSecretByID fetches a single secret by ID for the specified user.
	GetSecretByID(ctx context.Context, userID string, id string) (*models.Secret, error)
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
// If the client's lastKnownVersion is behind the store's current version,
// it returns the latest secrets from the store. Otherwise, it upserts
// the provided secrets and returns them.
// Returns a map with keys "version" (int64) and "secrets" ([]models.Secret).
func (s *SyncService) Sync(ctx context.Context, userID string, secrets []models.Secret, lastKnownVersion int64) (map[string]any, error) {
	currentVersion, err := s.repo.GetMaxVersion(ctx, userID)
	if err != nil {
		return nil, err
	}

	if lastKnownVersion < currentVersion {
		latest, err := s.repo.GetSecretsByUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"version": currentVersion, "secrets": latest}, nil
	}

	if err := s.repo.UpsertSecrets(ctx, userID, secrets); err != nil {
		return nil, err
	}

	return map[string]any{"version": lastKnownVersion, "secrets": secrets}, nil
}

// Delete removes the specified secrets for the user from the data store.
func (s *SyncService) Delete(ctx context.Context, userID string, ids []string) error {
	return s.repo.DeleteSecrets(ctx, userID, ids)
}

// GetByID retrieves a single secret by its ID for the given user.
func (s *SyncService) GetByID(ctx context.Context, userID string, id string) (*models.Secret, error) {
	return s.repo.GetSecretByID(ctx, userID, id)
}
