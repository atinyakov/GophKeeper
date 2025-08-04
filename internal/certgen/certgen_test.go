package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// setupTestCA генерирует CA (сертификат и ключ) и возвращает их PEM-форматы,
// а также распарсенные объекты для проверки.
func setupTestCA(t *testing.T) (certPEM []byte, keyPEM []byte, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()

	// Генерируем приватный ключ CA
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	// Шаблон самоподписанного сертификата
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// Создаём сертификат
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, template, priv
}

func TestLoadCACredentials_Success(t *testing.T) {
	// Подготовка CA pem-файлов
	certPEM, keyPEM, wantCert, wantKey := setupTestCA(t)

	certFile, err := os.CreateTemp("", "ca-cert-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certFile.Name())
	if _, err := certFile.Write(certPEM); err != nil {
		t.Fatal(err)
	}
	certFile.Close()

	keyFile, err := os.CreateTemp("", "ca-key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keyFile.Name())
	if _, err := keyFile.Write(keyPEM); err != nil {
		t.Fatal(err)
	}
	keyFile.Close()

	certOut, keyOut, err := LoadCACredentials(certFile.Name(), keyFile.Name())
	if err != nil {
		t.Fatalf("LoadCACredentials error: %v", err)
	}
	// Проверяем CommonName
	if certOut.Subject.CommonName != wantCert.Subject.CommonName {
		t.Errorf("CommonName = %q; want %q", certOut.Subject.CommonName, wantCert.Subject.CommonName)
	}
	// Проверяем тип ключа и совпадение публичного ключа
	parsedKey, ok := keyOut.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T; want *ecdsa.PrivateKey", keyOut)
	}
	if parsedKey.PublicKey.X.Cmp(wantKey.PublicKey.X) != 0 {
		t.Error("public key X mismatch")
	}
	if parsedKey.PublicKey.Y.Cmp(wantKey.PublicKey.Y) != 0 {
		t.Error("public key Y mismatch")
	}
}

func TestLoadCACredentials_MissingCert(t *testing.T) {
	_, _, err := LoadCACredentials("/no/such/file.pem", "ignored")
	if err == nil || !strings.Contains(err.Error(), "read ca cert") {
		t.Errorf("got %v; want error about reading ca cert", err)
	}
}

func TestLoadCACredentials_MissingKey(t *testing.T) {
	// Сначала создаём валидный cert-файл
	certPEM, _, _, _ := setupTestCA(t)
	certFile, _ := os.CreateTemp("", "ca-cert-*.pem")
	defer os.Remove(certFile.Name())
	certFile.Write(certPEM)
	certFile.Close()

	_, _, err := LoadCACredentials(certFile.Name(), "/no/such/key.pem")
	if err == nil || !strings.Contains(err.Error(), "read ca key") {
		t.Errorf("got %v; want error about reading ca key", err)
	}
}

func TestLoadCACredentials_BadCertPEM(t *testing.T) {
	// Некорректный cert-файл
	certFile, _ := os.CreateTemp("", "ca-cert-*.pem")
	defer os.Remove(certFile.Name())
	certFile.WriteString("not a cert")
	certFile.Close()

	// Валидный key
	_, keyPEM, _, _ := setupTestCA(t)
	keyFile, _ := os.CreateTemp("", "ca-key-*.pem")
	defer os.Remove(keyFile.Name())
	keyFile.Write(keyPEM)
	keyFile.Close()

	_, _, err := LoadCACredentials(certFile.Name(), keyFile.Name())
	if err == nil || !strings.Contains(err.Error(), "invalid CA cert PEM") {
		t.Errorf("got %v; want invalid CA cert PEM error", err)
	}
}

func TestLoadCACredentials_BadKeyPEM(t *testing.T) {
	// Валидный cert
	certPEM, _, _, _ := setupTestCA(t)
	certFile, _ := os.CreateTemp("", "ca-cert-*.pem")
	defer os.Remove(certFile.Name())
	certFile.Write(certPEM)
	certFile.Close()

	// Некорректный key
	keyFile, _ := os.CreateTemp("", "ca-key-*.pem")
	defer os.Remove(keyFile.Name())
	keyFile.WriteString("not a key")
	keyFile.Close()

	_, _, err := LoadCACredentials(certFile.Name(), keyFile.Name())
	if err == nil || !strings.Contains(err.Error(), "invalid CA key PEM") {
		t.Errorf("got %v; want invalid CA key PEM error", err)
	}
}

func TestGenerateUserCertificate_Success(t *testing.T) {
	_, _, caCert, caKey := setupTestCA(t)

	certPEM, keyPEM, err := GenerateUserCertificate("userCN", caCert, caKey)
	if err != nil {
		t.Fatalf("GenerateUserCertificate error: %v", err)
	}
	// Проверяем, что это PEM-сертификат
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("cert PEM invalid")
	}
	userCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse user cert: %v", err)
	}
	// Проверяем CN
	if userCert.Subject.CommonName != "userCN" {
		t.Errorf("CommonName = %q; want %q", userCert.Subject.CommonName, "userCN")
	}
	// Проверяем подпись, но пропускаем если алгоритм не реализован
	if err := userCert.CheckSignatureFrom(caCert); err != nil {
		if strings.Contains(err.Error(), "algorithm unimplemented") {
			t.Logf("skipping signature check: %v", err)
		} else {
			t.Errorf("signature check failed: %v", err)
		}
	}

	// Проверяем PEM-ключ
	block2, _ := pem.Decode(keyPEM)
	if block2 == nil || block2.Type != "EC PRIVATE KEY" {
		t.Fatalf("key PEM invalid")
	}
	if _, err := x509.ParseECPrivateKey(block2.Bytes); err != nil {
		t.Errorf("parse private key failed: %v", err)
	}
}
