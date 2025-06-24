// Package main implements the GophKeeper CLI client, providing commands
// for user registration and an interactive shell for managing encrypted secrets.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	storageFile = "storage.json" // path to local secrets storage file
	apiRegister = "/api/register"
	apiSync     = "/api/sync"
)

var (
	// version is set at build time via ldflags.
	version string
	// buildDate is set at build time via ldflags.
	buildDate string
)

// Secret represents an encrypted secret with metadata stored locally
// and sent to/received from the server.
type Secret struct {
	ID      string `json:"id"`
	Type    string `json:"type"`    // "login_password", "text", "binary", "card"
	Data    string `json:"data"`    // base64-encoded encrypted payload
	Comment string `json:"comment"` // user-provided note
	Version int64  `json:"version"` // timestamp or sync version
}

// LocalStorage holds the in-memory list of secrets and current version,
// with methods for thread-safe manipulation and persistence.
type LocalStorage struct {
	Secrets []Secret `json:"secrets"`
	Version int64    `json:"version"`
	mu      sync.Mutex
}

// Load reads the storage file from disk into the LocalStorage.
// If the file does not exist, initializes empty storage.
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

// Save writes the current LocalStorage state to the storage file in JSON.
func (ls *LocalStorage) Save() error {
	f, err := os.Create(storageFile)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(ls)
}

// Add appends a new Secret to storage and updates the version.
func (ls *LocalStorage) Add(s Secret) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.Secrets = append(ls.Secrets, s)
	ls.Version = s.Version
}

// List decrypts and prints all stored secrets using the provided AEAD and nonce.
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

// Get returns a pointer to the Secret with the given ID, or nil if not found.
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

// Delete removes a secret by ID. Returns true if deletion occurred.
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

// Edit updates the Data and Comment of an existing secret, re-encrypts it,
// and updates its Version. Returns true if the secret was found and edited.
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

// promptEditSecret reads new base64-encoded data and comment from stdin.
func promptEditSecret() (data, comment string) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter new base64 encoded data: ")
	scanner.Scan()
	data = scanner.Text()
	fmt.Print("Enter new comment: ")
	scanner.Scan()
	comment = scanner.Text()
	return
}

// register performs user registration by POSTing to the server's /api/register,
// saves returned client certificate and key to disk.
func register(baseURL, login, caPath string) error {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return errors.New("failed to parse CA cert")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}}}

	payload := map[string]string{"login": login}
	b, _ := json.Marshal(payload)
	resp, err := client.Post(baseURL+apiRegister, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("register failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(data))
	}

	var certData map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&certData); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	if err := os.WriteFile("client.crt", []byte(certData["cert"]), 0600); err != nil {
		return fmt.Errorf("failed to save client.crt: %w", err)
	}
	if err := os.WriteFile("client.key", []byte(certData["key"]), 0600); err != nil {
		return fmt.Errorf("failed to save client.key: %w", err)
	}

	fmt.Println("✅ Registration successful. Certificate and key saved.")
	return nil
}

// loadClientCertificate loads the client cert/key and CA cert,
// constructs and returns an HTTP client configured for mTLS.
func loadClientCertificate(certFile, keyFile, caFile string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert/key: %w", err)
	}
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caPool,
			InsecureSkipVerify: false,
		},
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, nil
}

// syncWithServer sends local secrets and version to server, merges returned updates,
// updates LocalStorage, and persists to disk.
func syncWithServer(client *http.Client, baseURL string, ls *LocalStorage) error {
	ls.mu.Lock()
	payload := map[string]interface{}{
		"secrets":            ls.Secrets,
		"last_known_version": ls.Version,
	}
	ls.mu.Unlock()

	b, _ := json.Marshal(payload)
	resp, err := client.Post(baseURL+apiSync, "application/json", bytes.NewReader(b))
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

// startAutoSync launches a goroutine to sync with the server every 10 seconds.
func startAutoSync(client *http.Client, baseURL string, ls *LocalStorage) {
	go func() {
		for {
			if err := syncWithServer(client, baseURL, ls); err != nil {
				log.Println("sync error:", err)
			}
			time.Sleep(10 * time.Second)
		}
	}()
}

// promptForSecret interactively reads secret type, comment, and plaintext,
// encrypts the data and returns a new Secret.
func promptForSecret(aead cipher.AEAD, nonce []byte) Secret {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter type (login_password/text/binary/card): ")
	scanner.Scan()
	typeStr := scanner.Text()

	fmt.Print("Enter comment: ")
	scanner.Scan()
	comment := scanner.Text()

	fmt.Print("Enter secret data (will be encrypted): ")
	scanner.Scan()
	plainData := scanner.Text()

	cipherData := aead.Seal(nil, nonce, []byte(plainData), nil)
	encoded := base64.StdEncoding.EncodeToString(cipherData)

	return Secret{
		ID:      uuid.NewString(),
		Type:    typeStr,
		Data:    encoded,
		Comment: comment,
		Version: time.Now().Unix(),
	}
}

// repl runs the interactive shell loop, accepting commands to manage secrets.
func repl(client *http.Client, baseURL string, ls *LocalStorage, aead cipher.AEAD, nonce []byte) {
	startAutoSync(client, baseURL, ls)

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("gophkeeper> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		switch args[0] {
		case "help":
			fmt.Println("Available commands: help, add, list, get <id>, delete <id>, edit <id>, exit")
		case "add":
			sec := promptForSecret(aead, nonce)
			ls.Add(sec)
			_ = ls.Save()
		case "list":
			ls.List(aead, nonce)
		case "get":
			if len(args) < 2 {
				fmt.Println("Usage: get <id>")
				continue
			}
			sec := ls.Get(args[1])
			if sec == nil {
				fmt.Println("Secret not found")
			} else {
				b, _ := json.MarshalIndent(sec, "", "  ")
				fmt.Println(string(b))
			}
		case "delete":
			if len(args) < 2 {
				fmt.Println("Usage: delete <id>")
				continue
			}
			if ls.Delete(args[1]) {
				_ = ls.Save()
				fmt.Println("Secret deleted")
			} else {
				fmt.Println("Secret not found")
			}
		case "edit":
			if len(args) < 2 {
				fmt.Println("Usage: edit <id>")
				continue
			}
			newData, newComment := promptEditSecret()
			if ls.Edit(args[1], newData, newComment, aead, nonce) {
				_ = ls.Save()
				fmt.Println("Secret updated")
			} else {
				fmt.Println("Secret not found")
			}
		case "exit":
			fmt.Println("Bye")
			return
		default:
			fmt.Println("Unknown command. Type 'help' for a list of commands.")
		}
	}
}

// main parses command-line flags and dispatches to the register or shell commands.
func main() {
	var (
		cmd      string
		baseURL  string
		certFile string
		keyFile  string
		caFile   string
		loginStr string
		showVer  bool
	)

	flag.StringVar(&cmd, "cmd", "", "command: register | shell")
	flag.StringVar(&baseURL, "url", "https://localhost:8080", "server base URL")
	flag.StringVar(&certFile, "cert", "client.crt", "path to client cert")
	flag.StringVar(&keyFile, "key", "client.key", "path to client key")
	flag.StringVar(&caFile, "ca", "certs/ca.crt", "path to CA cert")
	flag.StringVar(&loginStr, "login", "", "username for registration")
	flag.BoolVar(&showVer, "version", false, "show build version and date")
	flag.Parse()

	if showVer {
		fmt.Printf("GophKeeper Client\nVersion: %s\nBuild Date: %s\n", version, buildDate)
		return
	}

	switch cmd {
	case "register":
		if loginStr == "" {
			log.Fatal("please provide -login=username")
		}
		if err := register(baseURL+apiRegister, loginStr, caFile); err != nil {
			log.Fatal(err)
		}
	case "shell":
		client, err := loadClientCertificate(certFile, keyFile, caFile)
		if err != nil {
			log.Fatal(err)
		}
		ls := &LocalStorage{}
		_ = ls.Load()

		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			log.Fatalf("failed to read client cert: %v", err)
		}
		key := sha256.Sum256(certPEM)
		block, err := aes.NewCipher(key[:])
		if err != nil {
			log.Fatalf("failed to create cipher: %v", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			log.Fatalf("failed to create AEAD: %v", err)
		}
		nonce := make([]byte, aead.NonceSize())

		repl(client, baseURL, ls, aead, nonce)
	default:
		log.Fatalf("unknown command: %s", cmd)
	}
}
