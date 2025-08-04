package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	caCert, caKey := generateCA()

	// IsCA + BasicConstraintsValid
	if !caCert.IsCA {
		t.Error("CA certificate should have IsCA=true")
	}
	if !caCert.BasicConstraintsValid {
		t.Error("CA certificate should have BasicConstraintsValid=true")
	}

	// KeyUsage includes CertSign and DigitalSignature
	wantKU := x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	if caCert.KeyUsage&wantKU != wantKU {
		t.Errorf("CA KeyUsage = %v; want bits %v", caCert.KeyUsage, wantKU)
	}

	// Validity ~10 years
	dur := caCert.NotAfter.Sub(caCert.NotBefore)
	if dur < 9*365*24*time.Hour {
		t.Errorf("CA validity too short: %v", dur)
	}

	// RSA key size check (should be at least 2048 bits, your code uses 4096)
	if caKey.N.BitLen() < 2048 {
		t.Errorf("CA RSA key too small: %d bits", caKey.N.BitLen())
	}
}

func TestGenerateCert_Localhost(t *testing.T) {
	caCert, caKey := generateCA()
	cert, key := generateCert("localhost", caCert, caKey)

	// Subject CN
	if cert.Subject.CommonName != "localhost" {
		t.Errorf("CommonName = %q; want \"localhost\"", cert.Subject.CommonName)
	}

	// DNSNames
	if !reflect.DeepEqual(cert.DNSNames, []string{"localhost"}) {
		t.Errorf("DNSNames = %v; want [\"localhost\"]", cert.DNSNames)
	}

	// Signed by CA
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("certificate not signed by CA: %v", err)
	}

	// KeyUsage
	wantKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if cert.KeyUsage&wantKU != wantKU {
		t.Errorf("KeyUsage = %v; want bits %v", cert.KeyUsage, wantKU)
	}

	// ExtKeyUsage includes ClientAuth+ServerAuth
	foundClient, foundServer := false, false
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageClientAuth:
			foundClient = true
		case x509.ExtKeyUsageServerAuth:
			foundServer = true
		}
	}
	if !foundClient || !foundServer {
		t.Errorf("ExtKeyUsage = %v; want both ClientAuth and ServerAuth", cert.ExtKeyUsage)
	}

	// RSA key size
	if key.N.BitLen() < 2048 {
		t.Errorf("RSA key too small: %d bits", key.N.BitLen())
	}
}

func TestGenerateCert_CustomCN(t *testing.T) {
	caCert, caKey := generateCA()
	name := "alice"
	cert, _ := generateCert(name, caCert, caKey)

	// DNSNames = CN
	if !reflect.DeepEqual(cert.DNSNames, []string{name}) {
		t.Errorf("DNSNames = %v; want [%q]", cert.DNSNames, name)
	}
}

func TestWriteCertAndKey_RoundTrip(t *testing.T) {
	// prepare a temp dir
	dir := t.TempDir()
	certPath := filepath.Join(dir, "foo.crt")
	keyPath := filepath.Join(dir, "foo.key")

	// generate a cert/key pair
	caCert, caKey := generateCA()

	// write them out
	writeCertAndKey(certPath, keyPath, caCert, caKey)

	// read & parse cert
	crtPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	block, _ := pem.Decode(crtPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM block; got %v", block)
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	if !reflect.DeepEqual(parsedCert.Raw, caCert.Raw) {
		t.Error("parsed certificate does not match original")
	}

	// read & parse key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("expected RSA PRIVATE KEY PEM block; got %v", block)
	}
	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	// compare modulus & exponent
	origKey := caKey
	if origKey.N.Cmp(parsedKey.N) != 0 || origKey.E != parsedKey.E {
		t.Error("parsed private key does not match original")
	}
}
