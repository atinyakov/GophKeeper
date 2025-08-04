package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func StartAutoSync(client *http.Client, baseURL string, ls *LocalStorage) {
	go func() {
		for {
			err := SyncWithServer(client, baseURL, ls)
			if err != nil {
				fmt.Println("sync error:", err)
			}
			time.Sleep(10 * time.Second)
		}
	}()
}

func SyncWithServer(client *http.Client, baseURL string, ls *LocalStorage) error {
	ls.mu.Lock()
	payload := map[string]interface{}{
		"secrets":            ls.Secrets,
		"last_known_version": ls.Version,
	}
	ls.mu.Unlock()

	b, _ := json.Marshal(payload)
	resp, err := client.Post(baseURL+"/api/sync", "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", strings.TrimSpace(string(data)))
	}

	var result struct {
		Secrets []Secret `json:"secrets"`
		Version int64    `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	ls.mu.Lock()
	ls.Secrets = make([]Secret, len(result.Secrets))
	copy(ls.Secrets, result.Secrets)
	ls.Version = result.Version
	ls.mu.Unlock()

	return ls.Save()
}
