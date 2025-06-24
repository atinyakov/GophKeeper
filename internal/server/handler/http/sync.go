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
	// Sync processes the client's secrets and version, returning
	// a map containing the updated version and the slice of secrets to sync.
	//   ctx:     request context for cancellation and deadlines
	//   userID:  identifier of the authenticated user
	//   secrets: slice of models.Secret submitted by the client
	//   version: client's last known version
	// Returns a map with keys "version" (int64) and "secrets" ([]models.Secret),
	// or an error if syncing fails.
	Sync(ctx context.Context, userID string, secrets []models.Secret, version int64) (map[string]any, error)
}

// SyncHandler handles HTTP requests for secret synchronization.
type SyncHandler struct {
	// SyncService performs the underlying synchronization logic.
	SyncService SyncService
}

// Sync handles POST /api/sync requests.
// It decodes a JSON body with "secrets" and "last_known_version",
// invokes the SyncService, and writes the resulting map as JSON.
//
//	w: HTTP response writer
//	r: HTTP request, must have been authenticated via middleware
func (h *SyncHandler) Sync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.GetUserIDFromContext(ctx)

	// Decode request payload
	var req struct {
		Secrets          []models.Secret `json:"secrets"`
		LastKnownVersion int64           `json:"last_known_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	// Perform synchronization
	result, err := h.SyncService.Sync(ctx, userID, req.Secrets, req.LastKnownVersion)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
