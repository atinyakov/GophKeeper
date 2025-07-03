package db

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
    login TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    user_login TEXT REFERENCES users(login) ON DELETE CASCADE,
    type TEXT NOT NULL,
    data BYTEA NOT NULL,
    comment TEXT,
    version BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT FALSE
);
`

func InitPostgres(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return db, nil
}
