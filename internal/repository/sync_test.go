package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/atinyakov/GophKeeper/internal/models"
	repo "github.com/atinyakov/GophKeeper/internal/repository"
	"github.com/lib/pq"
)

func setupMock(t *testing.T) (*repo.PostgresSyncRepository, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock database: %v", err)
	}
	service := repo.NewPostgresSyncRepostitory(db)
	cleanup := func() { db.Close() }
	return service, mock, cleanup
}

func TestGetMaxVersion(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "user1"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COALESCE\(MAX\(version\), 0\) FROM secrets WHERE user_login = \$1 AND deleted = false`)).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"coalesce"}).AddRow(int64(7)))

	v, err := service.GetMaxVersion(context.Background(), userID)
	if err != nil || v != 7 {
		t.Errorf("unexpected result: %v, err: %v", v, err)
	}
}

func TestGetSecretsByUser(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "alice"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, type, data, comment, version, deleted FROM secrets WHERE user_login = \$1 AND deleted = false`)).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "type", "data", "comment", "version", "deleted"}).
			AddRow("id1", "pass", "data1", "comment1", int64(1), false))

	list, err := service.GetSecretsByUser(context.Background(), userID)
	if err != nil || len(list) != 1 || list[0].ID != "id1" {
		t.Errorf("unexpected result: %+v, err: %v", list, err)
	}
}

// func TestUpsertSecrets(t *testing.T) {
// 	service, mock, cleanup := setupMock(t)
// 	defer cleanup()

// 	userID := "userX"
// 	secrets := []models.Secret{{ID: "id1", Type: "t1", Data: "d1", Comment: "c1", Version: 2}}

// 	mock.ExpectBegin()
// 	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO secrets \(id, user_login, type, data, comment, version, deleted\)`)).
// 		WithArgs("id1", userID, "t1", "d1", "c1", int64(2), false).
// 		WillReturnResult(sqlmock.NewResult(1, 1))
// 	mock.ExpectCommit()

// 	err := service.UpsertSecrets(context.Background(), userID, secrets)
// 	if err != nil {
// 		t.Errorf("unexpected error: %v", err)
// 	}
// }

func TestDeleteSecrets(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "bob"
	ids := []string{"id1", "id2"}
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE secrets SET deleted = true WHERE user_login = \$1 AND id = ANY\(\$2\)`)).
		WithArgs(userID, pq.Array(ids)).
		WillReturnResult(sqlmock.NewResult(0, 2))

	err := service.DeleteSecrets(context.Background(), userID, ids)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetSecretByID(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "user1"
	id := "sec1"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, type, data, comment, version, deleted FROM secrets`)).
		WithArgs(userID, id).
		WillReturnRows(sqlmock.NewRows([]string{"id", "type", "data", "comment", "version", "deleted"}).
			AddRow(id, "t", "d", "c", int64(3), false))

	secret, err := service.GetSecretByID(context.Background(), userID, id)
	if err != nil || secret.ID != id {
		t.Errorf("unexpected: %+v, err: %v", secret, err)
	}
}

func TestUpsertIfNewer_SkipsOlder(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "u1"
	secret := models.Secret{ID: "s1", Type: "t", Data: "d", Comment: "c", Version: 5}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT version FROM secrets WHERE id = $1 AND user_login = $2 AND deleted = false`)).
		WithArgs(secret.ID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(6)))
	mock.ExpectCommit()

	updated, skipped, err := service.UpsertIfNewer(context.Background(), userID, []models.Secret{secret})
	if err != nil || len(updated) != 0 || len(skipped) != 1 {
		t.Errorf("unexpected result: updated=%v skipped=%v err=%v", updated, skipped, err)
	}
}

func TestUpsertIfNewer_UpdatesNewer(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "u2"
	secret := models.Secret{ID: "s1", Type: "t", Data: "d", Comment: "c", Version: 10}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT version FROM secrets WHERE id = $1 AND user_login = $2 AND deleted = false`)).
		WithArgs(secret.ID, userID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO secrets \(id, user_login, type, data, comment, version, deleted\)`)).
		WithArgs(secret.ID, userID, secret.Type, secret.Data, secret.Comment, secret.Version, false).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	updated, skipped, err := service.UpsertIfNewer(context.Background(), userID, []models.Secret{secret})
	if err != nil || len(updated) != 1 || updated[0] != "s1" {
		t.Errorf("unexpected: updated=%v skipped=%v err=%v", updated, skipped, err)
	}
}

func TestGetNewerSecrets(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	userID := "userN"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, type, data, comment, version, deleted FROM secrets WHERE user_login = $1 AND deleted = false`)).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "type", "data", "comment", "version", "deleted"}).
			AddRow("id1", "t", "d", "c", int64(5), false))

	list, err := service.GetNewerSecrets(context.Background(), userID, map[string]int64{"id1": 2})
	if err != nil || len(list) != 1 {
		t.Errorf("unexpected result: %+v, err: %v", list, err)
	}
}

func TestGetMaxVersion_Error(t *testing.T) {
	service, mock, cleanup := setupMock(t)
	defer cleanup()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COALESCE\(MAX\(version\), 0\) FROM secrets WHERE user_login = \$1 AND deleted = false`)).
		WithArgs("failuser").
		WillReturnError(errors.New("db error"))

	_, err := service.GetMaxVersion(context.Background(), "failuser")
	if err == nil {
		t.Errorf("expected error")
	}
}
