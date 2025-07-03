// Package http provides HTTP handlers for secret synchronization.
package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/atinyakov/GophKeeper/internal/middleware"
	"github.com/atinyakov/GophKeeper/internal/models"
)

// SyncService defines the interface for synchronization operations
// required by the SyncHandler.
type SyncService interface {
	// Sync processes the client's secrets and version map, returning
	// a map containing the updated version and the slice of new/updated secrets.
	//   ctx:     request context for cancellation and deadlines
	//   userID:  identifier of the authenticated user
	//   secrets: slice of models.Secret submitted by the client
	//   versions: map of secret ID to version held by the client
	// Returns a map with keys "version" (int64) and "secrets" ([]models.Secret),
	// or an error if syncing fails.
	Sync(ctx context.Context, userID string, secrets []models.Secret, versions map[string]int64) (map[string]any, error)
}

// SyncHandler handles HTTP requests for secret synchronization.
type SyncHandler struct {
	SyncService SyncService
}

// Sync handles POST /api/sync requests.
// It decodes a JSON body with "secrets" and "versions",
// invokes the SyncService, and writes the resulting map as JSON.
func (h *SyncHandler) Sync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.GetUserIDFromContext(ctx)

	var req struct {
		Secrets  []models.Secret  `json:"secrets"`
		Versions map[string]int64 `json:"versions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	// Perform synchronization
	result, err := h.SyncService.Sync(ctx, userID, req.Secrets, req.Versions)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
