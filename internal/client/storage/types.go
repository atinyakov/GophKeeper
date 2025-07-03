package storage

// Secret represents an encrypted secret with metadata stored locally
// and sent to/received from the server.
type Secret struct {
	ID      string `json:"id"`
	Type    string `json:"type"`    // "login_password", "text", "binary", "card"
	Data    string `json:"data"`    // base64-encoded encrypted payload
	Comment string `json:"comment"` // user-provided note
	Version int64  `json:"version"` // timestamp or sync version
	Deleted bool   `json:"deleted,omitempty"`
}
