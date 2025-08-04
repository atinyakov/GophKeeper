package storage

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeAEADPromt struct{}

func (fakeAEADPromt) NonceSize() int                              { return 0 }
func (fakeAEADPromt) Overhead() int                               { return 0 }
func (fakeAEADPromt) Seal(dst, nonce, plaintext, _ []byte) []byte { return append(dst, plaintext...) }
func (fakeAEADPromt) Open(dst, nonce, ciphertext, _ []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

func TestPromptForSecret(t *testing.T) {

	input := "login_password\nmycomment\nsecretdata\n"
	oldIn := os.Stdin
	defer func() { os.Stdin = oldIn }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString(input)
	w.Close()
	os.Stdin = r

	sec := PromptForSecret(fakeAEADPromt{})

	if sec.Type != "login_password" {
		t.Errorf("Type = %q; want %q", sec.Type, "login_password")
	}
	if sec.Comment != "mycomment" {
		t.Errorf("Comment = %q; want %q", sec.Comment, "mycomment")
	}
	if sec.ID == "" {
		t.Error("ID must not be empty")
	}
	if sec.Version < time.Now().Unix()-5 {
		t.Errorf("Version seems wrong: %d", sec.Version)
	}

	decoded, err := base64.StdEncoding.DecodeString(sec.Data)
	if err != nil {
		t.Fatalf("failed to decode Data: %v", err)
	}
	if got := string(decoded); got != "secretdata" {
		t.Errorf("Data = %q; want %q", got, "secretdata")
	}
}

func TestPromptEditSecret_FilePath(t *testing.T) {

	tmp, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("filecontent")
	if _, err := tmp.Write(content); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	input := tmp.Name() + "\nnewcomment\n"
	oldIn, oldOut := os.Stdin, os.Stdout
	defer func() {
		os.Stdin = oldIn
		os.Stdout = oldOut
	}()

	rIn, wIn, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = wIn.WriteString(input)
	wIn.Close()
	os.Stdin = rIn

	_, wOut, _ := os.Pipe()
	os.Stdout = wOut

	data, comment := PromptEditSecret()

	wOut.Close()
	os.Stdout = oldOut

	if string(data) != string(content) {
		t.Errorf("data = %q; want %q", string(data), string(content))
	}
	if comment != "newcomment" {
		t.Errorf("comment = %q; want %q", comment, "newcomment")
	}
}

func TestPromptEditSecret_Manual(t *testing.T) {

	input := "\nmanualdata\nmanualcomment\n"
	oldIn := os.Stdin
	defer func() { os.Stdin = oldIn }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString(input)
	w.Close()
	os.Stdin = r

	data, comment := PromptEditSecret()
	if string(data) != "manualdata" {
		t.Errorf("data = %q; want %q", string(data), "manualdata")
	}
	if comment != "manualcomment" {
		t.Errorf("comment = %q; want %q", comment, "manualcomment")
	}
}

func TestPromptEditSecret_FileNotFound(t *testing.T) {

	input := "/no/such/file\n\n"
	oldIn, oldOut := os.Stdin, os.Stdout
	defer func() {
		os.Stdin = oldIn
		os.Stdout = oldOut
	}()

	rIn, wIn, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = wIn.WriteString(input)
	wIn.Close()
	os.Stdin = rIn

	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	data, comment := PromptEditSecret()

	wOut.Close()
	os.Stdout = oldOut
	outBuf, _ := io.ReadAll(rOut)

	if data != nil {
		t.Errorf("data = %v; want nil", data)
	}
	if comment != "" {
		t.Errorf("comment = %q; want empty", comment)
	}
	if !strings.Contains(string(outBuf), "Failed to read file") {
		t.Errorf("expected error message in output, got %q", outBuf)
	}
}
