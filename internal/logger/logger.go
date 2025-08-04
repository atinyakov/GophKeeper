// Package logger provides a simple logging utility using the Zap logger.
package logger

import (
	"go.uber.org/zap"
)

// Logger is a wrapper around the Zap logger to handle logging functionality.
type Logger struct {
	// Log is the underlying Zap logger instance.
	Log *zap.Logger
}

// New creates and returns a new Logger instance with a no-op logger.
func New() *Logger {
	return &Logger{
		Log: zap.NewNop(), // No-op logger initially
	}
}

// Init initializes the Logger instance with the specified logging level.
// The level string is parsed into a Zap AtomicLevel, which defines the log level for the logger.
// The logger is then created based on a production configuration with the specified level.
// If an error occurs during initialization, it is returned.
func (l *Logger) Init(level string) error {
	// Parse the level string into a zap.AtomicLevel
	lvl, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return err
	}

	// Create a new logger configuration with production settings
	cfg := zap.NewProductionConfig()

	// Set the log level
	cfg.Level = lvl

	// Build the logger using the configuration
	zl, err := cfg.Build()
	if err != nil {
		return err
	}

	// Set the logger instance
	l.Log = zl
	return nil
}
