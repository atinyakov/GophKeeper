// Package main initializes and starts the GophKeeper HTTPS server,
// setting up configuration, logging, database connections, repositories,
// services, handlers, and TLS.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	nethttp "net/http"

	"github.com/atinyakov/GophKeeper/internal/config"
	"github.com/atinyakov/GophKeeper/internal/db"
	"github.com/atinyakov/GophKeeper/internal/logger"
	"github.com/atinyakov/GophKeeper/internal/repository"
	"github.com/atinyakov/GophKeeper/internal/server/handler/http"
	"github.com/atinyakov/GophKeeper/internal/service"
	"go.uber.org/zap"
)

var (
	// version holds the build version set via ldflags.
	version string
	// buildDate holds the build timestamp set via ldflags.
	buildDate string
)

func main() {
	// Parse command-line and environment configuration.
	options := config.Parse()
	addr := options.Port
	dbName := options.DatabaseDSN

	// Print build metadata (or "N/A" if unset).
	fmt.Printf("Build version: %s\n", cmp.Or(version, "N/A"))
	fmt.Printf("Build date: %s\n", cmp.Or(buildDate, "N/A"))

	// Initialize structured logging.
	log := logger.New()
	defer func() { _ = log.Log.Sync() }()
	if err := log.Init("Info"); err != nil {
		log.Log.Fatal("failed to init logger", zap.Error(err))
	}
	zapLogger := log.Log

	// Initialize PostgreSQL connection.
	postgressDB, err := db.InitPostgres(dbName)
	if err != nil {
		zapLogger.Fatal("cannot init database", zap.Error(err))
	}

	// Initialize PostgreSQL clean
	db.StartSoftDeleteCleaner(context.Background(), postgressDB,
		time.Hour,       // interval
		30*24*time.Hour, // retention: 30 days
		zapLogger,
	)

	// Initialize repositories for authentication and synchronization.
	authRepo := repository.NewPostgresAuthRepository(postgressDB)
	syncRepo := repository.NewPostgresSyncRepostitory(postgressDB)

	// Initialize business-logic services.
	authService := service.NewAuthService(authRepo)
	syncService := service.NewSyncService(syncRepo)

	// Create HTTP handlers for auth and sync endpoints.
	authHandler := &http.AuthHandler{AuthService: authService}
	syncHandler := &http.SyncHandler{SyncService: syncService}

	// Build the router with middleware and routes.
	router := http.NewRouter(authHandler, syncHandler, zapLogger)

	// Load server TLS certificate and key.
	cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		zapLogger.Fatal("failed to load server TLS cert/key", zap.Error(err))
	}

	// Load and append CA certificate for client cert verification.
	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		zapLogger.Fatal("failed to read CA cert", zap.Error(err))
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		zapLogger.Fatal("failed to append CA cert to pool")
	}

	// Configure TLS to require or verify client certificates.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create and start the HTTPS server.
	server := &nethttp.Server{
		Addr:      addr,
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	zapLogger.Info("starting HTTPS server", zap.String("addr", addr))
	if err := server.ListenAndServeTLS("", ""); err != nil {
		zapLogger.Fatal("failed to start HTTPS server", zap.Error(err))
	}
}
