package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// generateTestRSAKey produces a PEM‐encoded RSA private key for tests.
func generateTestRSAKey(t *testing.T) []byte {
	// use crypto/rand.Reader instead of nil
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func TestNewAEADFromKeyPEM(t *testing.T) {
	keyPEM := generateTestRSAKey(t)

	aead1, err := NewAEADFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("derive AEAD failed: %v", err)
	}
	aead2, err := NewAEADFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("derive AEAD second time: %v", err)
	}

	// same private key => same AEAD key, so we can encrypt with aead1 and decrypt with aead2
	nonce := make([]byte, aead1.NonceSize())
	ciphertext := aead1.Seal(nonce, nonce, []byte("helloworld"), nil)

	// decrypt using the second AEAD instance
	plain, err := aead2.Open(nil, nonce, ciphertext[aead2.NonceSize():], nil)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(plain, []byte("helloworld")) {
		t.Errorf("unexpected plaintext: got %q, want %q", plain, "helloworld")
	}
}
