package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helper: generate a self-signed CA cert and key
func generateCACert(t *testing.T) (certPEM, keyPEM []byte, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	certTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, certTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, cert, key
}

func TestRegister_ReadCAError(t *testing.T) {
	err := Register("http://example.com", "user", "nonexistent.pem")
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected file not exist error, got %v", err)
	}
}

func TestRegister_InvalidCA(t *testing.T) {
	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.pem")
	// write invalid PEM
	if err := os.WriteFile(caPath, []byte("invalid pem"), 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	err := Register("http://example.com", "user", caPath)
	if err == nil || !strings.Contains(err.Error(), "failed to parse CA cert") {
		t.Errorf("expected parse CA error, got %v", err)
	}
}

func TestRegister_ServerError(t *testing.T) {
	// setup valid CA
	tmp := t.TempDir()
	caPEM, _, _, _ := generateCACert(t)
	caPath := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	// test server returns 500
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("oops"))
	}))
	defer ts.Close()

	err := Register(ts.URL, "user", caPath)
	if err == nil || !strings.Contains(err.Error(), "server error: oops") {
		t.Errorf("expected server error message, got %v", err)
	}
}

func TestRegister_Success(t *testing.T) {
	// setup CA and server
	tmp := t.TempDir()
	caPEM, _, _, _ := generateCACert(t)
	caPath := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	respBody := map[string]string{"cert": "certdata", "key": "keydata"}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respBody)
	}))
	defer ts.Close()

	// change working dir to tmp for file writes
	cwd, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(cwd)

	err := Register(ts.URL, "user", caPath)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	// check files
	crt, err := os.ReadFile("client.crt")
	if err != nil || string(crt) != "certdata" {
		t.Errorf("unexpected cert file content: %s, err: %v", crt, err)
	}
	key, err := os.ReadFile("client.key")
	if err != nil || string(key) != "keydata" {
		t.Errorf("unexpected key file content: %s, err: %v", key, err)
	}
}

func TestLoadClientCertificate(t *testing.T) {
	// generate client cert/key
	certPEM, keyPEM, _, _ := generateCACert(t)
	// use same cert as CA
	caPEM := certPEM

	// write files
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "client.crt")
	keyPath := filepath.Join(tmp, "client.key")
	caPath := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	client, err := LoadClientCertificate(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// check TLS config
	tcfg := client.Transport.(*http.Transport).TLSClientConfig
	if len(tcfg.Certificates) != 1 {
		t.Errorf("expected 1 client certificate, got %d", len(tcfg.Certificates))
	}
	// verify root CAs contains our CA
	subs := tcfg.RootCAs.Subjects()
	found := false
	for _, subj := range subs {
		if bytes.Contains(subj, []byte("Test CA")) {
			found = true
			break
		}
	}
	if !found {
		t.Error("CA certificate not found in RootCAs")
	}
}
