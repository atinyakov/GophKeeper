package repository

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func setupAuthMock(t *testing.T) (*PostgresAuthRepository, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock database: %v", err)
	}
	service := NewPostgresAuthRepository(db)
	cleanup := func() { db.Close() }
	return service, mock, cleanup
}

func TestUserExists_True(t *testing.T) {
	service, mock, cleanup := setupAuthMock(t)
	defer cleanup()

	login := "user1"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM users WHERE login = $1)`)).
		WithArgs(login).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	exists, err := service.UserExists(context.Background(), login)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Errorf("expected user to exist, got false")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUserExists_False(t *testing.T) {
	service, mock, cleanup := setupAuthMock(t)
	defer cleanup()

	login := "user2"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM users WHERE login = $1)`)).
		WithArgs(login).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	exists, err := service.UserExists(context.Background(), login)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Errorf("expected user to not exist, got true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUserExists_Error(t *testing.T) {
	service, mock, cleanup := setupAuthMock(t)
	defer cleanup()

	login := "user3"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM users WHERE login = $1)`)).
		WithArgs(login).
		WillReturnError(errors.New("query failed"))

	_, err := service.UserExists(context.Background(), login)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRegisterUser_Success(t *testing.T) {
	service, mock, cleanup := setupAuthMock(t)
	defer cleanup()

	login := "newuser"
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO users (login) VALUES ($1)`)).
		WithArgs(login).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := service.RegisterUser(context.Background(), login)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRegisterUser_Error(t *testing.T) {
	service, mock, cleanup := setupAuthMock(t)
	defer cleanup()

	login := "dupuser"
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO users (login) VALUES ($1)`)).
		WithArgs(login).
		WillReturnError(errors.New("insert failed"))

	err := service.RegisterUser(context.Background(), login)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
