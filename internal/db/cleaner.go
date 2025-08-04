package db

import (
	"context"
	"database/sql"
	"time"

	"go.uber.org/zap"
)

// StartSoftDeleteCleaner deleted old secrets with interval
func StartSoftDeleteCleaner(
	ctx context.Context,
	db *sql.DB,
	interval time.Duration,
	retention time.Duration,
	log *zap.Logger,
) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-retention).Unix()
				res, err := db.ExecContext(ctx, `
                    DELETE FROM secrets
                     WHERE deleted = true
                       AND version < $1
                `, cutoff)
				if err != nil {
					log.Error("failed to clean soft-deleted secrets", zap.Error(err))
					continue
				}
				if rows, _ := res.RowsAffected(); rows > 0 {
					log.Info("cleaned soft-deleted secrets", zap.Int64("removed", rows))
				}
			}
		}
	}()
}
