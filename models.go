package mcpauth

import "time"

// OAuthToken represents an issued access or refresh token.
// Kind is "access" or "refresh". Raw token values (Token, RefreshToken)
// are transient and never persisted to disk. Only their SHA-256 hashes
// are stored.
type OAuthToken struct {
	Token        string    `json:"token,omitempty"`
	TokenHash    string    `json:"token_hash"`
	Kind         string    `json:"kind,omitempty"`
	UserID       string    `json:"user_id"`
	Resource     string    `json:"resource"`
	Scopes       []string  `json:"scopes,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	RefreshHash  string    `json:"refresh_hash,omitempty"`
	ClientID     string    `json:"client_id,omitempty"`
}

// OAuthClient represents a dynamically registered OAuth client.
type OAuthClient struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	SecretHash              string   `json:"secret_hash,omitempty"`
	IssuedAt                int64    `json:"client_id_issued_at,omitempty"`
	UserID                  string   `json:"user_id,omitempty"`
}

// APIKey represents a pre-configured API key for Bearer token authentication.
// Unlike OAuth tokens, API keys are permanent and only removed by revocation.
type APIKey struct {
	KeyHash   string    `json:"key_hash"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Code represents a pending authorization code. Ephemeral, never persisted.
// Codes start active and are marked inactive on first use. A second
// attempt to consume an inactive code is treated as a replay attack
// (RFC 6819 Section 4.4.1.1).
type Code struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	UserID        string
	Scopes        []string
	ExpiresAt     time.Time
	active        bool
}
