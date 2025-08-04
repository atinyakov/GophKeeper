package storage

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

func PromptForSecret(aead cipher.AEAD) Secret {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter type (login_password/text/binary/card): ")
	scanner.Scan()
	typeStr := scanner.Text()

	fmt.Print("Enter comment: ")
	scanner.Scan()
	comment := scanner.Text()

	fmt.Print("Enter secret data (will be encrypted): ")
	scanner.Scan()
	plain := scanner.Text()

	// Генерируем крипто-стойкий nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("failed to generate nonce: %v", err)
	}
	// Шифруем: результат = nonce || ciphertext
	ciphertext := aead.Seal(nonce, nonce, []byte(plain), nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return Secret{
		ID:      uuid.NewString(),
		Type:    typeStr,
		Data:    encoded,
		Comment: comment,
		Version: time.Now().Unix(),
	}
}

// PromptEditSecret edit secret from shell
func PromptEditSecret() (data []byte, comment string) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter file path to load (leave empty for manual input): ")
	scanner.Scan()
	path := strings.TrimSpace(scanner.Text())

	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			fmt.Printf("Failed to read file %q: %v\n", path, err)
			return nil, ""
		}
	} else {
		fmt.Print("Enter new data: ")
		scanner.Scan()
		data = []byte(scanner.Text())
	}
	fmt.Print("Enter new comment: ")
	scanner.Scan()
	comment = scanner.Text()

	return data, comment
}
