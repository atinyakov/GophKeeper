// Package main generates a Certificate Authority (CA), server, and client certificates,
// writing them to files under the "certs" directory.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	// certs directory for storing generated certificates and keys
	dir := "certs"
	_ = os.MkdirAll(dir, 0755)

	// 1. Generate CA certificate and key
	caCert, caKey := generateCA()
	writeCertAndKey(dir+"/ca.crt", dir+"/ca.key", caCert, caKey)

	// 2. Generate server certificate/key signed by CA
	serverCert, serverKey := generateCert("localhost", caCert, caKey)
	writeCertAndKey(dir+"/server.crt", dir+"/server.key", serverCert, serverKey)

	// 3. Generate client certificate/key signed by CA
	clientCert, clientKey := generateCert("alice", caCert, caKey)
	writeCertAndKey(dir+"/client.crt", dir+"/client.key", clientCert, clientKey)

	fmt.Println("✅ Certificates generated into ./certs")
}

// generateCA creates a self-signed CA certificate and its RSA private key.
// The CA is valid for 10 years and can sign other certificates.
func generateCA() (*x509.Certificate, *rsa.PrivateKey) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "GophKeeper CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(caBytes)
	return cert, caKey
}

// generateCert creates a certificate and RSA private key for the given common name (cn),
// signed by the provided CA certificate and key. The certificate is valid for one year.
// If cn == "localhost", the SAN DNS name "localhost" is added; otherwise, the CN is used.
func generateCert(cn string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add Subject Alternative Names (SAN)
	if cn == "localhost" {
		certTmpl.DNSNames = []string{"localhost"}
	} else {
		certTmpl.DNSNames = []string{cn}
	}

	privKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	certBytes, _ := x509.CreateCertificate(rand.Reader, certTmpl, ca, &privKey.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certBytes)
	return cert, privKey
}

// writeCertAndKey writes the given certificate and private key to the specified file paths.
// The certificate is PEM-encoded as "CERTIFICATE" and the key as "RSA PRIVATE KEY".
func writeCertAndKey(certPath, keyPath string, cert *x509.Certificate, key *rsa.PrivateKey) {
	certOut, _ := os.Create(certPath)
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	_ = certOut.Close()

	keyOut, _ := os.Create(keyPath)
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_ = keyOut.Close()
}
