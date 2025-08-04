package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// roundTripperFunc позволяет удобно замокать http.Client.
type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestClient(fn roundTripperFunc) *http.Client {
	return &http.Client{Transport: fn, Timeout: time.Second}
}

func TestSyncWithServer_NetworkError(t *testing.T) {
	ls := &LocalStorage{}
	client := newTestClient(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})
	err := SyncWithServer(client, "http://example.com", ls)
	if err == nil || !strings.Contains(err.Error(), "sync failed") {
		t.Errorf("expected network failure, got %v", err)
	}
}

func TestSyncWithServer_ServerError(t *testing.T) {
	ls := &LocalStorage{}
	client := newTestClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(strings.NewReader("internal error\n")),
		}, nil
	})
	err := SyncWithServer(client, "http://example.com", ls)
	if err == nil || !strings.Contains(err.Error(), "server error: internal error") {
		t.Errorf("expected server error, got %v", err)
	}
}

func TestSyncWithServer_InvalidJSON(t *testing.T) {
	ls := &LocalStorage{}
	client := newTestClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not-json")),
		}, nil
	})
	err := SyncWithServer(client, "http://example.com", ls)
	if err == nil || !strings.Contains(err.Error(), "invalid response") {
		t.Errorf("expected JSON decode error, got %v", err)
	}
}

func TestSyncWithServer_Success(t *testing.T) {
	dir := t.TempDir()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		_ = os.Chdir(origDir)
	}()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	ls := &LocalStorage{}
	nowVersion := int64(42)
	wantSecrets := []Secret{
		{ID: "s1", Type: "t1", Data: "d1", Comment: "c1", Version: nowVersion},
	}

	// Заглушка HTTP-сервера
	client := newTestClient(func(req *http.Request) (*http.Response, error) {
		// Проверим, что отправляется правильный URL и метод
		if req.URL.String() != "http://example.com/api/sync" {
			t.Errorf("unexpected URL: %s", req.URL)
		}
		// Подтвердим, что в теле запроса были пустые secrets и version=0
		var payload struct {
			Secrets          []Secret `json:"secrets"`
			LastKnownVersion int64    `json:"last_known_version"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request failed: %v", err)
		}
		if len(payload.Secrets) != 0 || payload.LastKnownVersion != 0 {
			t.Errorf("unexpected request payload: %+v", payload)
		}

		// Возвращаем успешный ответ
		respBody, _ := json.Marshal(map[string]interface{}{
			"secrets": wantSecrets,
			"version": nowVersion,
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	})

	// Выполняем синхронизацию
	if err := SyncWithServer(client, "http://example.com", ls); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Проверяем, что LocalStorage обновился
	if ls.Version != nowVersion {
		t.Errorf("version = %d; want %d", ls.Version, nowVersion)
	}
	if len(ls.Secrets) != 1 || ls.Secrets[0].ID != "s1" {
		t.Errorf("secrets = %+v; want %+v", ls.Secrets, wantSecrets)
	}

	// Проверим, что файл storage.json действительно записан
	data, err := os.ReadFile(filepath.Join(dir, "storage.json"))
	if err != nil {
		t.Fatalf("read storage.json failed: %v", err)
	}
	var onDisk LocalStorage
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("unmarshal storage.json failed: %v", err)
	}
	if onDisk.Version != nowVersion || len(onDisk.Secrets) != 1 || onDisk.Secrets[0].ID != "s1" {
		t.Errorf("file content = %+v; want %+v", onDisk, *ls)
	}
}
