package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// NewAEADFromKeyPEM parses a PEM-encoded private key (RSA or ECDSA),
// hashes its DER bytes to a 32-byte key, and returns an AES-GCM AEAD.
func NewAEADFromKeyPEM(keyPEM []byte) (cipher.AEAD, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("storage: failed to decode PEM")
	}

	der := block.Bytes
	// sanity-check parsing
	switch block.Type {
	case "RSA PRIVATE KEY":
		if _, err := x509.ParsePKCS1PrivateKey(der); err != nil {
			return nil, fmt.Errorf("storage: parse RSA: %w", err)
		}
	case "EC PRIVATE KEY":
		if _, err := x509.ParseECPrivateKey(der); err != nil {
			return nil, fmt.Errorf("storage: parse ECDSA: %w", err)
		}
	case "PRIVATE KEY":
		if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
			return nil, fmt.Errorf("storage: parse PKCS8: %w", err)
		}
	default:
		return nil, fmt.Errorf("storage: unsupported key type %q", block.Type)
	}

	// derive 32-byte key by hashing the private-key DER
	sum := sha256.Sum256(der)
	blockCipher, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("storage: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, fmt.Errorf("storage: cipher.NewGCM: %w", err)
	}
	return aead, nil
}
