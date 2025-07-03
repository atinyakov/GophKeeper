package storage

import (
	"crypto/cipher"
	"crypto/rand"
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
	deleted map[string]bool `json:"-"`
}

const storageFile = "storage.json"

func (ls *LocalStorage) Load() error {
	f, err := os.Open(storageFile)
	if err != nil {
		if os.IsNotExist(err) {
			ls.Secrets = []Secret{}
			ls.Version = 0
			ls.deleted = make(map[string]bool)
			return nil
		}
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(ls); err != nil {
		return err
	}
	ls.deleted = make(map[string]bool)
	for _, s := range ls.Secrets {
		if s.Deleted {
			ls.deleted[s.ID] = true
		}
	}
	return nil
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

func (ls *LocalStorage) List(aead cipher.AEAD) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	fmt.Println("Stored secrets:")
	for _, s := range ls.Secrets {
		if s.Deleted || ls.deleted[s.ID] {
			continue
		}
		cipherData, err := base64.StdEncoding.DecodeString(s.Data)
		if err != nil || len(cipherData) < aead.NonceSize() {
			fmt.Printf("ID: %s (decode error)\n", s.ID)
			continue
		}
		nonce := cipherData[:aead.NonceSize()]
		data := cipherData[aead.NonceSize():]
		plain, err := aead.Open(nil, nonce, data, nil)
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
		if s.ID == id && !s.Deleted && !ls.deleted[id] {
			return &s
		}
	}
	return nil
}

func (ls *LocalStorage) Delete(id string) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if ls.deleted == nil {
		ls.deleted = make(map[string]bool)
	}

	for i, s := range ls.Secrets {
		if s.ID == id && !s.Deleted {
			ls.Secrets[i].Deleted = true
			ls.Secrets[i].Version = time.Now().Unix()
			ls.deleted[id] = true
			return true
		}
	}
	return false
}

func (ls *LocalStorage) Edit(id string, newData []byte, newComment string, aead cipher.AEAD) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	for i, sec := range ls.Secrets {
		if sec.ID != id || sec.Deleted || ls.deleted[id] {
			continue
		}

		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			fmt.Println("failed to generate nonce:", err)
			return false
		}

		ct := aead.Seal(nonce, nonce, []byte(newData), nil)
		ls.Secrets[i].Data = base64.StdEncoding.EncodeToString(ct)
		ls.Secrets[i].Comment = newComment
		ls.Secrets[i].Version = time.Now().Unix()
		return true
	}
	return false
}
