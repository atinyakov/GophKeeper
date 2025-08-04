package service

import (
	"context"
	"errors"
	"testing"
)

type mockAuthRepo struct {
	UserExistsFunc   func(ctx context.Context, login string) (bool, error)
	RegisterUserFunc func(ctx context.Context, login string) error
}

func (m *mockAuthRepo) UserExists(ctx context.Context, login string) (bool, error) {
	return m.UserExistsFunc(ctx, login)
}
func (m *mockAuthRepo) RegisterUser(ctx context.Context, login string) error {
	return m.RegisterUserFunc(ctx, login)
}

func TestUserExists_Success(t *testing.T) {
	want := true
	repo := &mockAuthRepo{
		UserExistsFunc: func(ctx context.Context, login string) (bool, error) {
			if login != "bob" {
				t.Errorf("UserExists received login = %q; want %q", login, "bob")
			}
			return want, nil
		},
	}
	svc := NewAuthService(repo)

	got, err := svc.UserExists(context.Background(), "bob")
	if err != nil {
		t.Fatalf("UserExists returned error: %v", err)
	}
	if got != want {
		t.Errorf("UserExists = %v; want %v", got, want)
	}
}

func TestUserExists_Error(t *testing.T) {
	wantErr := errors.New("db error")
	repo := &mockAuthRepo{
		UserExistsFunc: func(ctx context.Context, login string) (bool, error) {
			return false, wantErr
		},
	}
	svc := NewAuthService(repo)

	got, err := svc.UserExists(context.Background(), "alice")
	if err != wantErr {
		t.Fatalf("UserExists error = %v; want %v", err, wantErr)
	}
	if got {
		t.Errorf("UserExists = %v; want false on error", got)
	}
}

func TestRegisterUser_Success(t *testing.T) {
	called := false
	repo := &mockAuthRepo{
		RegisterUserFunc: func(ctx context.Context, login string) error {
			called = true
			if login != "carol" {
				t.Errorf("RegisterUser received login = %q; want %q", login, "carol")
			}
			return nil
		},
	}
	svc := NewAuthService(repo)

	if err := svc.RegisterUser(context.Background(), "carol"); err != nil {
		t.Fatalf("RegisterUser returned error: %v", err)
	}
	if !called {
		t.Fatal("expected RegisterUser to be called on repo")
	}
}

func TestRegisterUser_Error(t *testing.T) {
	wantErr := errors.New("insert failed")
	repo := &mockAuthRepo{
		RegisterUserFunc: func(ctx context.Context, login string) error {
			return wantErr
		},
	}
	svc := NewAuthService(repo)

	err := svc.RegisterUser(context.Background(), "dave")
	if err != wantErr {
		t.Fatalf("RegisterUser error = %v; want %v", err, wantErr)
	}
}
