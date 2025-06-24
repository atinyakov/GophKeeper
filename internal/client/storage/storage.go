package storage

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type LocalStorage struct {
	Secrets []Secret `json:"secrets"`
	Version int64    `json:"version"`
	mu      sync.Mutex
}

const storageFile = "storage.json"

func (ls *LocalStorage) Load() error {
	f, err := os.Open(storageFile)
	if err != nil {
		if os.IsNotExist(err) {
			ls.Secrets = []Secret{}
			ls.Version = 0
			return nil
		}
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(ls)
}

func (ls *LocalStorage) Save() error {
	f, err := os.Create(storageFile)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(ls)
}

func (ls *LocalStorage) Add(s Secret) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.Secrets = append(ls.Secrets, s)
	ls.Version = s.Version
}

func (ls *LocalStorage) List(aead cipher.AEAD, nonce []byte) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	fmt.Println("Stored secrets:")
	for _, s := range ls.Secrets {
		cipherData, err := base64.StdEncoding.DecodeString(s.Data)
		if err != nil {
			fmt.Printf("ID: %s (failed to decode data)\n", s.ID)
			continue
		}
		plain, err := aead.Open(nil, nonce, cipherData, nil)
		if err != nil {
			fmt.Printf("ID: %s (decryption error)\n", s.ID)
			continue
		}
		fmt.Printf("ID: %s\nType: %s\nComment: %s\nData: %s\nVersion: %d\n---\n",
			s.ID, s.Type, s.Comment, string(plain), s.Version)
	}
}

func (ls *LocalStorage) Get(id string) *Secret {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for _, s := range ls.Secrets {
		if s.ID == id {
			return &s
		}
	}
	return nil
}

func (ls *LocalStorage) Delete(id string) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for i, s := range ls.Secrets {
		if s.ID == id {
			ls.Secrets = append(ls.Secrets[:i], ls.Secrets[i+1:]...)
			return true
		}
	}
	return false
}

func (ls *LocalStorage) Edit(id, newData, newComment string, aead cipher.AEAD, nonce []byte) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for i, s := range ls.Secrets {
		if s.ID == id {
			cipherData := aead.Seal(nil, nonce, []byte(newData), nil)
			s.Data = base64.StdEncoding.EncodeToString(cipherData)
			s.Comment = newComment
			s.Version = time.Now().Unix()
			ls.Secrets[i] = s
			return true
		}
	}
	return false
}
