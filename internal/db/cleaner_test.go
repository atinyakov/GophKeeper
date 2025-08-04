package db

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestStartSoftDeleteCleaner_Success(t *testing.T) {
	dbMock, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock database: %v", err)
	}
	defer dbMock.Close()

	mock.ExpectExec("DELETE FROM secrets").
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 3))

	logger := zap.NewNop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartSoftDeleteCleaner(ctx, dbMock, 10*time.Millisecond, time.Hour, logger)

	time.Sleep(200 * time.Millisecond)
	cancel()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStartSoftDeleteCleaner_ErrorLogged(t *testing.T) {
	dbMock, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock database: %v", err)
	}
	defer dbMock.Close()

	mock.ExpectExec("DELETE FROM secrets").
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(fmt.Errorf("db fail"))

	var buf bytes.Buffer
	encCfg := zap.NewDevelopmentEncoderConfig()
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encCfg),
		zapcore.AddSync(&buf),
		zapcore.ErrorLevel,
	)
	logger := zap.New(core)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartSoftDeleteCleaner(ctx, dbMock, 10*time.Millisecond, time.Hour, logger)

	time.Sleep(200 * time.Millisecond)
	cancel()

	out := buf.String()
	if !strings.Contains(out, "failed to clean soft-deleted secrets") {
		t.Errorf("expected error log, got:\n%s", out)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStartSoftDeleteCleaner_CancelBeforeTicker(t *testing.T) {
	dbMock, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock database: %v", err)
	}
	defer dbMock.Close()

	logger := zap.NewNop()
	ctx, cancel := context.WithCancel(context.Background())

	StartSoftDeleteCleaner(ctx, dbMock, 100*time.Millisecond, time.Hour, logger)
	cancel()

	time.Sleep(50 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected sql calls: %v", err)
	}
}
