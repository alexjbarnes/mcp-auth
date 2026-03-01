package mcpauth

import "context"

// Persistence defines the storage backend for tokens, clients, and API keys.
// Implementations must be safe for concurrent use.
// Pass nil to New() for in-memory-only operation (useful in tests).
type Persistence interface {
	SaveOAuthToken(token OAuthToken) error
	DeleteOAuthToken(tokenHash string) error
	AllOAuthTokens() ([]OAuthToken, error)

	SaveOAuthClient(client OAuthClient) error
	DeleteOAuthClient(clientID string) error
	AllOAuthClients() ([]OAuthClient, error)

	SaveAPIKey(hash string, key APIKey) error
	DeleteAPIKey(hash string) error
	AllAPIKeys() (map[string]APIKey, error)
}

// UserAuthenticator validates user credentials during the authorization
// code flow. Implementations may use bcrypt, SHA-256 comparison, LDAP,
// database lookup, or any other mechanism.
type UserAuthenticator interface {
	// ValidateCredentials checks username/password and returns the user ID
	// on success. Returns ("", nil) if credentials are invalid.
	// Returns non-nil error only for system failures (database down, etc.).
	ValidateCredentials(ctx context.Context, username, password string) (userID string, err error)
}

// UserAccountChecker is an optional interface that, when implemented by
// the Users value passed to Config, enables per-request user account
// validation. The middleware calls IsAccountActive after successful token
// validation to verify the user has not been disabled since the token
// was issued.
//
// If the Users value does not implement this interface, the middleware
// skips the check (backward compatible).
type UserAccountChecker interface {
	// IsAccountActive returns true if the user account is enabled.
	// Returns (false, nil) for disabled accounts.
	// Returns non-nil error only for system failures.
	IsAccountActive(ctx context.Context, userID string) (bool, error)
}
