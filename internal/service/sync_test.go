package service_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/atinyakov/GophKeeper/internal/models"
	"github.com/atinyakov/GophKeeper/internal/service"
)

type mockRepo struct {
	DeleteSecretsFunc    func(ctx context.Context, userID string, ids []string) error
	GetSecretByIDFunc    func(ctx context.Context, userID, id string) (*models.Secret, error)
	UpsertIfNewerFunc    func(ctx context.Context, userID string, secrets []models.Secret) ([]string, []string, error)
	GetNewerSecretsFunc  func(ctx context.Context, userID string, versions map[string]int64) ([]models.Secret, error)
	GetMaxVersionFunc    func(ctx context.Context, userID string) (int64, error)
	GetSecretsByUserFunc func(ctx context.Context, userID string) ([]models.Secret, error)
	UpsertSecretsFunc    func(ctx context.Context, userID string, secrets []models.Secret) error
}

func (m *mockRepo) DeleteSecrets(ctx context.Context, userID string, ids []string) error {
	return m.DeleteSecretsFunc(ctx, userID, ids)
}
func (m *mockRepo) GetSecretByID(ctx context.Context, userID, id string) (*models.Secret, error) {
	return m.GetSecretByIDFunc(ctx, userID, id)
}
func (m *mockRepo) UpsertIfNewer(ctx context.Context, userID string, secrets []models.Secret) ([]string, []string, error) {
	return m.UpsertIfNewerFunc(ctx, userID, secrets)
}
func (m *mockRepo) GetNewerSecrets(ctx context.Context, userID string, versions map[string]int64) ([]models.Secret, error) {
	return m.GetNewerSecretsFunc(ctx, userID, versions)
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

func TestSync_FullSync(t *testing.T) {
	syncSecrets := []models.Secret{{ID: "s1", Type: "t", Data: "d", Comment: "c", Version: 2}}
	clientVersions := map[string]int64{"s1": 1, "s2": 2}
	updated := []models.Secret{{ID: "s1", Type: "t", Data: "d2", Comment: "c", Version: 2}}

	repo := &mockRepo{
		UpsertIfNewerFunc: func(ctx context.Context, userID string, secrets []models.Secret) ([]string, []string, error) {
			return []string{"s1"}, nil, nil
		},
		GetNewerSecretsFunc: func(ctx context.Context, userID string, versions map[string]int64) ([]models.Secret, error) {
			if !reflect.DeepEqual(versions, clientVersions) {
				t.Errorf("GetNewerSecrets versions = %+v; want %+v", versions, clientVersions)
			}
			return updated, nil
		},
		GetMaxVersionFunc: func(ctx context.Context, userID string) (int64, error) {
			return 2, nil
		},
		GetSecretsByUserFunc: func(ctx context.Context, userID string) ([]models.Secret, error) {
			return nil, nil
		},
		UpsertSecretsFunc: func(ctx context.Context, userID string, secrets []models.Secret) error {
			return nil
		},
	}
	svc := service.NewSyncService(repo)

	res, err := svc.Sync(context.Background(), "u1", syncSecrets, clientVersions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := res["version"].(int64), int64(2); got != want {
		t.Errorf("version = %v; want %v", got, want)
	}
	if got, want := res["secrets"].([]models.Secret), updated; !reflect.DeepEqual(got, want) {
		t.Errorf("secrets = %+v; want %+v", got, want)
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
		UpsertSecretsFunc: func(ctx context.Context, userID string, secrets []models.Secret) error {
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
		UpsertSecretsFunc: func(ctx context.Context, userID string, secrets []models.Secret) error {
			return nil
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
