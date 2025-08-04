package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestWithRequestLogging(t *testing.T) {
	// Capture logs in a buffer using a custom zap logger
	var logBuf bytes.Buffer
	encoderCfg := zap.NewProductionEncoderConfig()
	encoder := zapcore.NewJSONEncoder(encoderCfg)
	writer := zapcore.AddSync(&logBuf)
	core := zapcore.NewCore(encoder, writer, zapcore.InfoLevel)
	logger := zap.New(core)

	// Create a dummy handler that writes a response
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusTeapot) // 418
		_, _ = w.Write([]byte("I'm a teapot"))
	})

	// Wrap the handler with logging middleware
	loggedHandler := WithRequestLogging(logger)(handler)

	// Create a test HTTP request and response recorder
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Call the wrapped handler
	loggedHandler.ServeHTTP(rec, req)

	// Check if the handler was called
	if !handlerCalled {
		t.Fatal("handler was not called")
	}

	// Check the response status and body
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("expected status 418, got %d", resp.StatusCode)
	}
	if string(body) != "I'm a teapot" {
		t.Errorf("unexpected response body: %s", body)
	}

	// Check if logs were written
	logOutput := logBuf.String()
	if logOutput == "" {
		t.Fatal("no logs written")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte(`"method":"GET"`)) {
		t.Error("log does not contain method field")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte(`"url":"/test"`)) {
		t.Error("log does not contain url field")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte(`"status":418`)) {
		t.Error("log does not contain status field")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte(`"size":12`)) {
		t.Error("log does not contain correct size field")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte(`"duration"`)) {
		t.Error("log does not contain duration field")
	}
}
