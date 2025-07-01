package middleware

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

// dummyHandler is a placeholder that records if it was called and the context it received.
type dummyHandler struct {
	called bool
	ctx    context.Context
}

func (d *dummyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.called = true
	d.ctx = r.Context()
	w.WriteHeader(http.StatusOK)
}

func TestCertAuth_RegisterPathBypass(t *testing.T) {
	dummy := &dummyHandler{}
	h := CertAuth(dummy)
	// simulate request to /api/register without TLS
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/register", nil)
	h.ServeHTTP(rec, req)

	if !dummy.called {
		t.Error("expected next handler to be called for /api/register")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec.Code)
	}
}

func TestCertAuth_NoCertificate(t *testing.T) {
	dummy := &dummyHandler{}
	h := CertAuth(dummy)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/data", nil)
	h.ServeHTTP(rec, req)

	if dummy.called {
		t.Error("did not expect next handler to be called when no certificate provided")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
	}
}

func TestCertAuth_ValidCertificate(t *testing.T) {
	// create fake certificate chain
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "alice"}}
	ts := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	dummy := &dummyHandler{}
	h := CertAuth(dummy)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.TLS = ts
	h.ServeHTTP(rec, req)

	if !dummy.called {
		t.Error("expected next handler to be called when valid certificate provided")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec.Code)
	}
	// verify context contains correct user
	user := GetUserIDFromContext(dummy.ctx)
	if user != "alice" {
		t.Errorf("expected context user 'alice', got '%s'", user)
	}
}

func TestGetUserIDFromContext(t *testing.T) {
	// no value
	empty := GetUserIDFromContext(context.Background())
	if empty != "" {
		t.Errorf("expected empty string for missing user, got '%s'", empty)
	}
	// with value
	ctx := context.WithValue(context.Background(), userKey, "bob")
	val := GetUserIDFromContext(ctx)
	if val != "bob" {
		t.Errorf("expected 'bob', got '%s'", val)
	}
}
