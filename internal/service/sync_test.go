package service_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/atinyakov/GophKeeper/internal/models"
	"github.com/atinyakov/GophKeeper/internal/service"
)

type mockRepo struct {
	GetMaxVersionFunc    func(ctx context.Context, userID string) (int64, error)
	GetSecretsByUserFunc func(ctx context.Context, userID string) ([]models.Secret, error)
	UpsertSecretsFunc    func(ctx context.Context, userID string, secrets []models.Secret) error
	DeleteSecretsFunc    func(ctx context.Context, userID string, ids []string) error
	GetSecretByIDFunc    func(ctx context.Context, userID, id string) (*models.Secret, error)
}

func (m *mockRepo) GetMaxVersion(ctx context.Context, userID string) (int64, error) {
	return m.GetMaxVersionFunc(ctx, userID)
}
func (m *mockRepo) GetSecretsByUser(ctx context.Context, userID string) ([]models.Secret, error) {
	return m.GetSecretsByUserFunc(ctx, userID)
}
func (m *mockRepo) UpsertSecrets(ctx context.Context, userID string, secrets []models.Secret) error {
	return m.UpsertSecretsFunc(ctx, userID, secrets)
}
func (m *mockRepo) DeleteSecrets(ctx context.Context, userID string, ids []string) error {
	return m.DeleteSecretsFunc(ctx, userID, ids)
}
func (m *mockRepo) GetSecretByID(ctx context.Context, userID, id string) (*models.Secret, error) {
	return m.GetSecretByIDFunc(ctx, userID, id)
}

func TestSync_VersionError(t *testing.T) {
	wantErr := errors.New("db down")
	repo := &mockRepo{
		GetMaxVersionFunc: func(context.Context, string) (int64, error) {
			return 0, wantErr
		},
	}
	svc := service.NewSyncService(repo)
	_, err := svc.Sync(context.Background(), "u1", nil, 0)
	if err != wantErr {
		t.Fatalf("Sync error = %v; want %v", err, wantErr)
	}
}

func TestSync_FetchLatestError(t *testing.T) {
	wantErr := errors.New("fetch failed")
	repo := &mockRepo{
		GetMaxVersionFunc: func(context.Context, string) (int64, error) {
			return 5, nil
		},
		GetSecretsByUserFunc: func(context.Context, string) ([]models.Secret, error) {
			return nil, wantErr
		},
	}
	svc := service.NewSyncService(repo)
	_, err := svc.Sync(context.Background(), "u1", nil, 2)
	if err != wantErr {
		t.Fatalf("Sync error = %v; want %v", err, wantErr)
	}
}

func TestSync_FetchLatestSuccess(t *testing.T) {
	latest := []models.Secret{
		{ID: "s1", Type: "t1", Data: "d1", Comment: "c1", Version: 7},
	}
	repo := &mockRepo{
		GetMaxVersionFunc: func(context.Context, string) (int64, error) {
			return 7, nil
		},
		GetSecretsByUserFunc: func(context.Context, string) ([]models.Secret, error) {
			return latest, nil
		},
	}
	svc := service.NewSyncService(repo)
	out, err := svc.Sync(context.Background(), "u1", []models.Secret{{ID: "ignored"}}, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotV, wantV := out["version"].(int64), int64(7); gotV != wantV {
		t.Errorf("version = %v; want %v", gotV, wantV)
	}
	if gotS, wantS := out["secrets"].([]models.Secret), latest; !reflect.DeepEqual(gotS, wantS) {
		t.Errorf("secrets = %+v; want %+v", gotS, wantS)
	}
}

func TestSync_UpsertError(t *testing.T) {
	wantErr := errors.New("upsert failed")
	repo := &mockRepo{
		GetMaxVersionFunc: func(context.Context, string) (int64, error) {
			return 2, nil
		},
		UpsertSecretsFunc: func(context.Context, string, []models.Secret) error {
			return wantErr
		},
	}
	svc := service.NewSyncService(repo)
	_, err := svc.Sync(context.Background(), "u1", []models.Secret{{ID: "sX"}}, 2)
	if err != wantErr {
		t.Fatalf("Sync error = %v; want %v", err, wantErr)
	}
}

func TestSync_UpsertSuccess(t *testing.T) {
	input := []models.Secret{
		{ID: "s2", Type: "t2", Data: "d2", Comment: "c2", Version: 9},
	}
	called := false
	repo := &mockRepo{
		GetMaxVersionFunc: func(context.Context, string) (int64, error) {
			return 9, nil
		},
		UpsertSecretsFunc: func(ctx context.Context, userID string, secrets []models.Secret) error {
			called = true
			if userID != "u1" {
				t.Errorf("UpsertSecrets userID = %q; want u1", userID)
			}
			if !reflect.DeepEqual(secrets, input) {
				t.Errorf("UpsertSecrets secrets = %+v; want %+v", secrets, input)
			}
			return nil
		},
	}
	svc := service.NewSyncService(repo)
	out, err := svc.Sync(context.Background(), "u1", input, 9)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected UpsertSecrets to be called")
	}
	if gotV := out["version"].(int64); gotV != 9 {
		t.Errorf("version = %v; want %v", gotV, 9)
	}
	if gotS, wantS := out["secrets"].([]models.Secret), input; !reflect.DeepEqual(gotS, wantS) {
		t.Errorf("secrets = %+v; want %+v", gotS, wantS)
	}
}

func TestDelete(t *testing.T) {
	ids := []string{"a", "b", "c"}
	called := false
	repo := &mockRepo{
		DeleteSecretsFunc: func(ctx context.Context, userID string, in []string) error {
			called = true
			if userID != "u42" {
				t.Errorf("DeleteSecrets userID = %q; want u42", userID)
			}
			if !reflect.DeepEqual(in, ids) {
				t.Errorf("DeleteSecrets ids = %v; want %v", in, ids)
			}
			return nil
		},
	}
	svc := service.NewSyncService(repo)
	if err := svc.Delete(context.Background(), "u42", ids); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if !called {
		t.Fatal("expected DeleteSecrets to be called")
	}
}

func TestGetByID(t *testing.T) {
	want := &models.Secret{ID: "xx", Type: "tt", Data: "dd", Comment: "cc", Version: 5}
	repo := &mockRepo{
		GetSecretByIDFunc: func(ctx context.Context, userID, id string) (*models.Secret, error) {
			if userID != "u7" || id != "xx" {
				t.Errorf("GetSecretByIDArgs = %q, %q; want u7, xx", userID, id)
			}
			return want, nil
		},
	}
	svc := service.NewSyncService(repo)
	got, err := svc.GetByID(context.Background(), "u7", "xx")
	if err != nil {
		t.Fatalf("GetByID error: %v", err)
	}
	if got != want {
		t.Fatalf("GetByID returned %p; want %p", got, want)
	}
}
