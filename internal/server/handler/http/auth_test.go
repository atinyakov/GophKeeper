package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAuthService implements AuthService for testing.
type fakeAuthService struct {
	existsReturn bool
	existsErr    error
	registerErr  error
}

func (f *fakeAuthService) UserExists(ctx context.Context, login string) (bool, error) {
	return f.existsReturn, f.existsErr
}

func (f *fakeAuthService) RegisterUser(ctx context.Context, login string) error {
	return f.registerErr
}

func TestAuthHandler_Register(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		service        *fakeAuthService
		expectedCode   int
		expectedSubstr string
	}{
		{
			name:           "invalid JSON",
			body:           `not a json`,
			service:        &fakeAuthService{},
			expectedCode:   http.StatusBadRequest,
			expectedSubstr: "invalid request",
		},
		{
			name:           "empty login",
			body:           `{"login":""}`,
			service:        &fakeAuthService{},
			expectedCode:   http.StatusBadRequest,
			expectedSubstr: "invalid request",
		},
		{
			name:           "UserExists error",
			body:           `{"login":"alice"}`,
			service:        &fakeAuthService{existsErr: errors.New("db error")},
			expectedCode:   http.StatusInternalServerError,
			expectedSubstr: "internal error",
		},
		{
			name:           "User already exists",
			body:           `{"login":"bob"}`,
			service:        &fakeAuthService{existsReturn: true},
			expectedCode:   http.StatusConflict,
			expectedSubstr: "user already exists",
		},
		{
			name:           "CA load failure",
			body:           `{"login":"charlie"}`,
			service:        &fakeAuthService{existsReturn: false},
			expectedCode:   http.StatusInternalServerError,
			expectedSubstr: "failed to load CA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/register", bytes.NewBufferString(tt.body))
			h := &AuthHandler{AuthService: tt.service}
			h.Register(rec, req)
			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tt.expectedCode {
				t.Fatalf("expected status %d, got %d", tt.expectedCode, res.StatusCode)
			}

			buf := new(bytes.Buffer)
			if _, err := buf.ReadFrom(res.Body); err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			if !bytes.Contains(buf.Bytes(), []byte(tt.expectedSubstr)) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedSubstr, buf.String())
			}
		})
	}
}

func TestAuthHandler_Login(t *testing.T) {
	tests := []struct {
		name         string
		tlsState     *tls.ConnectionState
		service      *fakeAuthService
		expectedCode int
		expectedJSON map[string]string
	}{
		{
			name:         "no TLS",
			tlsState:     nil,
			service:      &fakeAuthService{},
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "empty peer certs",
			tlsState:     &tls.ConnectionState{},
			service:      &fakeAuthService{},
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "UserExists error",
			tlsState:     &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "dave"}}}},
			service:      &fakeAuthService{existsErr: errors.New("db fail")},
			expectedCode: http.StatusInternalServerError,
		},
		{
			name:         "User not found",
			tlsState:     &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "erin"}}}},
			service:      &fakeAuthService{existsReturn: false},
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "Successful login",
			tlsState:     &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "frank"}}}},
			service:      &fakeAuthService{existsReturn: true},
			expectedCode: http.StatusOK,
			expectedJSON: map[string]string{"status": "ok", "user": "frank"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/login", nil)
			req.TLS = tt.tlsState

			h := &AuthHandler{AuthService: tt.service}
			h.Login(rec, req)
			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tt.expectedCode {
				t.Fatalf("%s: expected status %d, got %d", tt.name, tt.expectedCode, res.StatusCode)
			}

			if tt.expectedJSON != nil {
				var payload map[string]string
				if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
					t.Fatalf("failed to decode JSON: %v", err)
				}
				for k, v := range tt.expectedJSON {
					if payload[k] != v {
						t.Errorf("expected %s=%q, got %q", k, v, payload[k])
					}
				}
			}
		})
	}
}
