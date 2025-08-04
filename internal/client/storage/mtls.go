package storage

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func Register(baseURL, login, caPath string) error {
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
	resp, err := client.Post(baseURL, "application/json", bytes.NewReader(b))
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

	fmt.Println("\u2705 Registration successful. Certificate and key saved.")
	return nil
}

func LoadClientCertificate(certFile, keyFile, caFile string) (*http.Client, error) {
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
