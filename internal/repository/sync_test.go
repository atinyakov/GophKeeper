package repository

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/atinyakov/GophKeeper/internal/models"
	"github.com/lib/pq"
)

func setupMock(t *testing.T) (*PostgresSyncService, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock database: %v", err)
	}
	service := NewPostgresSyncService(db)
	cleanup := func() {
		db.Close()
	}
	return service, mock, cleanup
}

func TestGetMaxVersion_Success(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "user1"
	// Expect query and return version 5
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_login = $1`)).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"coalesce"}).AddRow(int64(5)))

	version, err := service.GetMaxVersion(context.Background(), userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != 5 {
		t.Errorf("expected version 5, got %d", version)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestGetMaxVersion_Error(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "user1"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_login = $1`)).
		WithArgs(userID).
		WillReturnError(errors.New("query fail"))

	_, err := service.GetMaxVersion(context.Background(), userID)
	if err == nil || !regexp.MustCompile(`GetMaxVersion failed`).MatchString(err.Error()) {
		t.Errorf("expected GetMaxVersion failed error, got %v", err)
	}
}

func TestGetSecretsByUser_Success(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "userA"
	rows := sqlmock.NewRows([]string{"id", "type", "data", "comment", "version"}).
		AddRow("1", "type1", "data1", "c1", int64(1)).
		AddRow("2", "type2", "data2", "c2", int64(2))

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, type, data, comment, version FROM secrets WHERE user_login = $1`)).
		WithArgs(userID).
		WillReturnRows(rows)

	secrets, err := service.GetSecretsByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets, got %d", len(secrets))
	}
	if secrets[0].ID != "1" || secrets[1].ID != "2" {
		t.Errorf("unexpected secrets returned: %+v", secrets)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUpsertSecrets_Success(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "userX"
	secrets := []models.Secret{
		{ID: "s1", Type: "t1", Data: "d1", Comment: "c1", Version: 1},
		{ID: "s2", Type: "t2", Data: "d2", Comment: "c2", Version: 2},
	}

	// Begin transaction
	mock.ExpectBegin()
	for _, s := range secrets {
		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO secrets (id, user_login, type, data, comment, version)`)).
			WithArgs(s.ID, userID, s.Type, s.Data, s.Comment, s.Version).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}
	mock.ExpectCommit()

	err := service.UpsertSecrets(context.Background(), userID, secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestDeleteSecrets_Success(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "userZ"
	ids := []string{"a", "b"}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM secrets WHERE user_login = $1 AND id = ANY($2)`)).
		WithArgs(userID, pq.Array(ids)).
		WillReturnResult(sqlmock.NewResult(0, 2))

	err := service.DeleteSecrets(context.Background(), userID, ids)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestGetSecretByID_Success(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "user9"
	id := "xyz"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, type, data, comment, version FROM secrets`)).
		WithArgs(userID, id).
		WillReturnRows(sqlmock.NewRows([]string{"id", "type", "data", "comment", "version"}).
			AddRow(id, "tt", "dd", "cc", int64(7)))

	sec, err := service.GetSecretByID(context.Background(), userID, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sec.ID != id || sec.Version != 7 {
		t.Errorf("got wrong secret: %+v", sec)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestSync_ReturnsFreshData(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "u1"
	// Transaction begin
	mock.ExpectBegin()
	// Current version in DB = 3
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_login = $1`)).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"coalesce"}).AddRow(int64(3)))
	// lastKnownVersion < currentVersion => fetch all
	rows := sqlmock.NewRows([]string{"id", "type", "data", "comment", "version"}).
		AddRow("i1", "ty", "da", "cm", int64(3))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, type, data, comment, version FROM secrets WHERE user_login = $1`)).
		WithArgs(userID).
		WillReturnRows(rows)
	mock.ExpectRollback()

	res, err := service.Sync(context.Background(), userID, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res["version"] != int64(3) {
		t.Errorf("expected version 3, got %v", res["version"])
	}
	secrets := res["secrets"].([]models.Secret)
	if len(secrets) != 1 || secrets[0].ID != "i1" {
		t.Errorf("unexpected secrets: %+v", secrets)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestSync_AppliesChanges(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "u2"
	newSecrets := []models.Secret{{ID: "n1", Type: "t", Data: "d", Comment: "c", Version: 10}}
	// Begin
	mock.ExpectBegin()
	// Current version = 0
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_login = $1`)).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"coalesce"}).AddRow(int64(0)))
	// Apply insert
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO secrets (id, user_login, type, data, comment, version)`)).
		WithArgs("n1", userID, "t", "d", "c", int64(10)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// Commit
	mock.ExpectCommit()

	res, err := service.Sync(context.Background(), userID, newSecrets, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res["version"] != int64(0) {
		t.Errorf("expected version 0, got %v", res["version"])
	}
	applied := res["secrets"].([]models.Secret)
	if len(applied) != 1 || applied[0].ID != "n1" {
		t.Errorf("unexpected applied secrets: %+v", applied)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
