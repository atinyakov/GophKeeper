// Package http provides HTTP handlers for secret synchronization.
package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/atinyakov/GophKeeper/internal/models"
	handler "github.com/atinyakov/GophKeeper/internal/server/handler/http"
)

// fakeSyncService records calls and returns preconfigured results.
type fakeSyncService struct {
	called           bool
	receivedUserID   string
	receivedSecrets  []models.Secret
	receivedVersions map[string]int64

	result map[string]any
	err    error
}

func (f *fakeSyncService) Sync(
	ctx context.Context,
	userID string,
	secrets []models.Secret,
	versions map[string]int64,
) (map[string]any, error) {
	f.called = true
	f.receivedUserID = userID
	f.receivedSecrets = secrets
	f.receivedVersions = versions
	return f.result, f.err
}

func TestSyncHandler_BadJSON(t *testing.T) {
	h := &handler.SyncHandler{SyncService: &fakeSyncService{}}
	req := httptest.NewRequest(http.MethodPost, "/api/sync", bytes.NewBufferString("not-a-json"))
	w := httptest.NewRecorder()

	h.Sync(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
	if body := w.Body.String(); body != "invalid body\n" {
		t.Errorf("body = %q; want %q", body, "invalid body\n")
	}
}

func TestSyncHandler_ServiceError(t *testing.T) {
	fake := &fakeSyncService{err: errors.New("sync failed")}
	h := &handler.SyncHandler{SyncService: fake}

	payload := map[string]any{
		"secrets":  []models.Secret{},
		"versions": map[string]int64{},
	}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/sync", bytes.NewReader(b))
	w := httptest.NewRecorder()

	h.Sync(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want %d", w.Code, http.StatusInternalServerError)
	}
	if body := w.Body.String(); body != "sync failed\n" {
		t.Errorf("body = %q; want %q", body, "sync failed\n")
	}
}

func TestSyncHandler_Success(t *testing.T) {
	wantVersion := int64(42)
	wantSecrets := []models.Secret{
		{ID: "id1", Type: "t1", Data: "d1", Comment: "c1", Version: 1},
	}
	wantVersions := map[string]int64{"id1": 1}
	fake := &fakeSyncService{
		result: map[string]any{
			"version": wantVersion,
			"secrets": wantSecrets,
		},
	}
	h := &handler.SyncHandler{SyncService: fake}

	reqBody := map[string]any{
		"secrets":  wantSecrets,
		"versions": wantVersions,
	}
	b, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/sync", bytes.NewReader(b))
	w := httptest.NewRecorder()

	h.Sync(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q; want %q", ct, "application/json")
	}

	var resp struct {
		Version int64           `json:"version"`
		Secrets []models.Secret `json:"secrets"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	if resp.Version != wantVersion {
		t.Errorf("version = %d; want %d", resp.Version, wantVersion)
	}
	if !reflect.DeepEqual(resp.Secrets, wantSecrets) {
		t.Errorf("secrets = %+v; want %+v", resp.Secrets, wantSecrets)
	}

	if !fake.called {
		t.Error("expected SyncService.Sync to be called")
	}
	if !reflect.DeepEqual(fake.receivedSecrets, wantSecrets) {
		t.Errorf("receivedSecrets = %+v; want %+v", fake.receivedSecrets, wantSecrets)
	}
	if !reflect.DeepEqual(fake.receivedVersions, wantVersions) {
		t.Errorf("receivedVersions = %+v; want %+v", fake.receivedVersions, wantVersions)
	}
}
