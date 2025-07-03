// Package models defines the core data structures for users and secrets.
package models

// User represents an application user with credentials.
type User struct {
	// ID is the unique identifier for the user.
	ID string
	// Username is the login name chosen by the user.
	Username string
	// PasswordHash is the hashed password of the user.
	PasswordHash []byte
}

// Secret holds encrypted information of various types, along with metadata.
type Secret struct {
	// ID is the unique identifier for the secret.
	ID string `json:"id"`
	// Type indicates the kind of secret ("login", "card", "binary", etc.).
	Type string `json:"type"`
	// Data contains the encrypted payload of the secret.
	Data string `json:"data"`
	// Comment holds user-provided metadata or notes about the secret.
	Comment string `json:"comment"`
	// Version is the sync version number for concurrency control.
	Version int64 `json:"version"`
	// Deleted
	Deleted bool `json:"deleted"`
}

// SecretType defines the set of valid secret type identifiers.
type SecretType string

const (
	// LoginPassword represents a secret containing a login and password.
	LoginPassword SecretType = "login_password"
	// TextData represents a secret containing plain text data.
	TextData SecretType = "text"
	// BinaryData represents a secret containing binary data.
	BinaryData SecretType = "binary"
	// CardData represents a secret containing card information (e.g., credit card).
	CardData SecretType = "card"
)
