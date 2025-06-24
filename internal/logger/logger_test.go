package logger_test

import (
	"testing"

	"github.com/atinyakov/GophKeeper/internal/logger"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestNew(t *testing.T) {
	l := logger.New()
	require.NotNil(t, l)
	require.NotNil(t, l.Log)
	require.NotNil(t, l.Log.Core())
}

func TestInit_ValidLevels(t *testing.T) {
	validLevels := []string{"debug", "info", "warn", "error", "dpanic", "panic", "fatal"}

	for _, level := range validLevels {
		t.Run(level, func(t *testing.T) {
			l := logger.New()
			err := l.Init(level)
			require.NoError(t, err)
			require.NotNil(t, l.Log)
			require.NotNil(t, l.Log.Core())

			// Check that the logger is enabled at the requested level or higher
			// For example, if level is "info", then InfoLevel.Enabled() should be true
			// We test that Enabled returns true for the requested level
			lvl, err := zapcore.ParseLevel(level)
			require.NoError(t, err)
			enabled := l.Log.Core().Enabled(lvl)
			require.True(t, enabled)
		})
	}
}

func TestInit_InvalidLevel(t *testing.T) {
	l := logger.New()
	err := l.Init("invalid_level")
	require.Error(t, err)
}
