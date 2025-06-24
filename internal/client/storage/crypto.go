package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
)

// NewAEADFromPEM derives an AEAD cipher from client cert PEM content.
func NewAEADFromPEM(certPEM []byte) (cipher.AEAD, []byte, error) {
	key := sha256.Sum256(certPEM)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create AEAD: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	return aead, nonce, nil
}
