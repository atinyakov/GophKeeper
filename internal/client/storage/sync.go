package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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

	var result struct {
		Secrets []Secret `json:"secrets"`
		Version int64    `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	ls.mu.Lock()
	for _, s := range result.Secrets {
		found := false
		for i := range ls.Secrets {
			if ls.Secrets[i].ID == s.ID {
				if s.Version > ls.Secrets[i].Version {
					ls.Secrets[i] = s
				}
				found = true
				break
			}
		}
		if !found {
			ls.Secrets = append(ls.Secrets, s)
		}
	}
	ls.Version = result.Version
	ls.mu.Unlock()

	fmt.Println("Sync successful")
	return ls.Save()
}
