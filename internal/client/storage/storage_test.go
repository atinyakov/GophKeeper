package storage

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeAEAD is a dummy AEAD that returns plaintext as-is and never errors.
type fakeAEAD struct{}

func (f fakeAEAD) NonceSize() int { return 12 }
func (f fakeAEAD) Overhead() int  { return 0 }
func (f fakeAEAD) Seal(dst, nonce, plaintext, aad []byte) []byte {
	return append(dst, plaintext...)
}
func (f fakeAEAD) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

func TestLoad_FileNotExist(t *testing.T) {
	// Use temp dir and chdir
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(dir)

	ls := &LocalStorage{}
	if err := ls.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(ls.Secrets) != 0 {
		t.Errorf("expected no secrets, got %d", len(ls.Secrets))
	}
	if ls.Version != 0 {
		t.Errorf("expected version 0, got %d", ls.Version)
	}
}

func TestLoad_FileExists(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(dir)

	// prepare file
	data := LocalStorage{
		Secrets: []Secret{{ID: "1", Type: "t", Data: "d", Comment: "c", Version: 5}},
		Version: 5,
	}
	buf, _ := json.Marshal(&data)
	os.WriteFile(storageFile, buf, 0644)

	ls := &LocalStorage{}
	if err := ls.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(ls.Secrets) != 1 || ls.Secrets[0].ID != "1" {
		t.Errorf("unexpected secrets: %+v", ls.Secrets)
	}
	if ls.Version != 5 {
		t.Errorf("expected version 5, got %d", ls.Version)
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(dir)

	ls := &LocalStorage{
		Secrets: []Secret{{ID: "2", Type: "x", Data: "y", Comment: "z", Version: 7}},
		Version: 7,
	}
	if err := ls.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	// read back
	buf, err := os.ReadFile(storageFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var out LocalStorage
	if err := json.Unmarshal(buf, &out); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if out.Version != 7 || len(out.Secrets) != 1 || out.Secrets[0].ID != "2" {
		t.Errorf("unexpected saved data: %+v", out)
	}
}

func TestAddGetDelete(t *testing.T) {
	ls := &LocalStorage{}
	s := Secret{ID: "a", Type: "t", Data: "d", Comment: "c", Version: 10}
	ls.Add(s)
	if len(ls.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(ls.Secrets))
	}
	if ls.Version != 10 {
		t.Errorf("expected version 10, got %d", ls.Version)
	}

	got := ls.Get("a")
	if got == nil || got.ID != "a" {
		t.Errorf("Get failed, got %+v", got)
	}

	if !ls.Delete("a") {
		t.Errorf("Delete returned false for existing id")
	}
	if ls.Delete("nonexistent") {
		t.Errorf("Delete returned true for nonexistent id")
	}
}

func TestEditAndList(t *testing.T) {
	// setup storage
	ls := &LocalStorage{}
	nonce := make([]byte, fakeAEAD{}.NonceSize())
	// add secret with plaintext "hello"
	plain := []byte("hello")
	cipherData := fakeAEAD{}.Seal(nil, nonce, plain, nil)
	ls.Add(Secret{ID: "1", Type: "x", Data: base64.StdEncoding.EncodeToString(cipherData), Comment: "old", Version: 1})

	// capture output

	stdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// edit secret
	timeBefore := time.Now().Unix()
	if !ls.Edit("1", "world", "newc", fakeAEAD{}, nonce) {
		t.Fatalf("Edit failed")
	}

	// list
	ls.List(fakeAEAD{}, nonce)

	// restore stdout and read
	w.Close()
	os.Stdout = stdout
	outBytes, _ := io.ReadAll(r)
	output := string(outBytes)

	if !strings.Contains(output, "ID: 1") || !strings.Contains(output, "Data: world") {
		t.Errorf("List output missing edited data: %s", output)
	}
	// verify version updated
	s2 := ls.Get("1")
	if s2 == nil || s2.Comment != "newc" || s2.Version < timeBefore {
		t.Errorf("Edit did not update comment/version: %+v", s2)
	}
}
