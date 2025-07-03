package db_test

import (
	"strings"
	"testing"

	"github.com/atinyakov/GophKeeper/internal/db"
)

func TestInitPostgres_ErrorPaths(t *testing.T) {
	cases := []struct {
		name       string
		dsn        string
		wantSubstr string
	}{
		{"invalid DSN", "some=random", "ping postgres"},
		{"empty DSN", "", "ping postgres"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.InitPostgres(tc.dsn)
			if err == nil {
				t.Fatalf("InitPostgres(%q) did not return error", tc.dsn)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("InitPostgres(%q) error = %q; want substring %q", tc.dsn, err.Error(), tc.wantSubstr)
			}
		})
	}
}
