// Package certgen provides utilities for loading a Certificate Authority (CA)
// certificate and key, and generating user certificates signed by that CA.
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// LoadCACredentials loads a CA certificate and its private key from PEM files.
// It returns the parsed *x509.Certificate, the private key (either *ecdsa.PrivateKey or *rsa.PrivateKey),
// or an error if reading or parsing fails.
//
//	certPath: filesystem path to the CA certificate PEM file
//	keyPath:  filesystem path to the CA private key PEM file
func LoadCACredentials(certPath, keyPath string) (*x509.Certificate, any, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("invalid CA key PEM")
	}
	var caKey any
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}

	return caCert, caKey, nil
}

// GenerateUserCertificate generates an ECDSA P-256 certificate for a user,
// signed by the provided CA certificate and key.
// It returns the PEM-encoded certificate and private key, or an error.
//
//	commonName: desired Common Name (CN) for the user certificate
//	caCert:     parsed CA *x509.Certificate for signing
//	caKey:      CA private key (*ecdsa.PrivateKey or *rsa.PrivateKey)
func GenerateUserCertificate(commonName string, caCert *x509.Certificate, caKey any) ([]byte, []byte, error) {
	// Generate a new ECDSA P-256 private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("gen key: %w", err)
	}

	// Create a serial number for the certificate
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now().Add(-1 * time.Minute),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Create and sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}

	// PEM-encode the certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	// Marshal and PEM-encode the private key
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal priv key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
