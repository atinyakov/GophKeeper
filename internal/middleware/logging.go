// Package middleware provides HTTP middleware functions that log request details
// such as the HTTP method, URL, response status, and response size.
package middleware

import (
	"net/http"
	"time"

	"go.uber.org/zap"
)

type (
	// responseData holds the status and size of an HTTP response.
	// It is used to capture response information for logging.
	responseData struct {
		status int // HTTP response status code
		size   int // Size of the HTTP response body
	}

	// loggingResponseWriter is a custom implementation of http.ResponseWriter
	// that captures the status code and response size for logging.
	loggingResponseWriter struct {
		http.ResponseWriter               // Embedding the original http.ResponseWriter
		responseData        *responseData // Pointer to the responseData structure
	}
)

// Write writes the response body to the client and tracks the size of the response.
func (r *loggingResponseWriter) Write(b []byte) (int, error) {
	// Writing the response body using the original http.ResponseWriter
	size, err := r.ResponseWriter.Write(b)
	r.responseData.size += size // Capture the size of the response
	return size, err
}

// WriteHeader sets the HTTP response status code and captures it for logging.
func (r *loggingResponseWriter) WriteHeader(statusCode int) {
	// Writing the status code using the original http.ResponseWriter
	r.ResponseWriter.WriteHeader(statusCode)
	r.responseData.status = statusCode // Capture the status code
}

// WithRequestLogging is an HTTP middleware that logs the details of each request.
// It logs the HTTP method, URL, response status, response size, and request duration.
func WithRequestLogging(log *zap.Logger) func(http.Handler) http.Handler {
	// Returns a middleware function that logs HTTP request details.
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Record the start time of the request
			start := time.Now()

			// Create a new responseData object to capture response details
			responseData := &responseData{
				status: 0, // Initial status is 0 (unspecified)
				size:   0, // Initial response size is 0
			}

			// Wrap the original ResponseWriter with the loggingResponseWriter
			lw := loggingResponseWriter{
				ResponseWriter: w,
				responseData:   responseData,
			}

			// Call the next handler in the chain
			next.ServeHTTP(&lw, r)

			// Calculate the duration of the request
			duration := time.Since(start)

			// Log the request details using the provided logger
			log.Info("HTTP Request",
				zap.String("method", r.Method),
				zap.String("url", r.URL.String()),
				zap.Duration("duration", duration),
				zap.Int("status", responseData.status),
				zap.Int("size", responseData.size),
			)
		})
	}
}
