package storage

import (
	"bufio"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
)

func PromptForSecret(aead cipher.AEAD, nonce []byte) Secret {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter type (login_password/text/binary/card): ")
	scanner.Scan()
	typeStr := scanner.Text()

	fmt.Print("Enter comment: ")
	scanner.Scan()
	comment := scanner.Text()

	fmt.Print("Enter secret data (will be encrypted): ")
	scanner.Scan()
	plainData := scanner.Text()

	cipherData := aead.Seal(nil, nonce, []byte(plainData), nil)
	encoded := base64.StdEncoding.EncodeToString(cipherData)

	return Secret{
		ID:      uuid.NewString(),
		Type:    typeStr,
		Data:    encoded,
		Comment: comment,
		Version: time.Now().Unix(),
	}
}

func PromptEditSecret() (string, string) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter new base64 encoded data: ")
	scanner.Scan()
	data := scanner.Text()
	fmt.Print("Enter new comment: ")
	scanner.Scan()
	comment := scanner.Text()
	return data, comment
}
