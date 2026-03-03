# mcp-auth

[![CI](https://github.com/alexjbarnes/mcp-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/alexjbarnes/mcp-auth/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/alexjbarnes/29da905d4adbb295641227b6b4858ae1/raw/coverage.json)](https://github.com/alexjbarnes/mcp-auth/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

OAuth 2.1 authorization server library for Go, designed for MCP (Model Context Protocol) servers.

Provides a complete OAuth 2.1 implementation with PKCE, dynamic client registration (RFC 7591), protected resource metadata (RFC 9728), and API key authentication. Wire the handlers into your HTTP mux and bring your own storage backend.

## Install

```
go get github.com/alexjbarnes/mcp-auth
```

## Quick start

```go
package main

import (
	"net/http"

	mcpauth "github.com/alexjbarnes/mcp-auth"
)

func main() {
	srv := mcpauth.New(mcpauth.Config{
		ServerURL: "https://example.com",
		Users:     mcpauth.NewMapAuthenticator(map[string]string{
			"alice": "password123",
		}),
		GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"},
	})
	defer srv.Stop()

	mux := http.NewServeMux()

	// Register all OAuth endpoints.
	srv.Register(mux)

	// Protect your application routes with the middleware.
	mux.Handle("/mcp", srv.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := mcpauth.RequestUserID(r.Context())
		w.Write([]byte("hello " + userID))
	})))

	http.ListenAndServe(":8080", mux)
}
```

## Endpoints

`srv.Register(mux)` wires:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| GET | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| POST | `/oauth/register` | Dynamic client registration (RFC 7591) |
| GET | `/oauth/authorize` | Authorization code flow (shows login page) |
| POST | `/oauth/authorize` | Authorization code flow (handles login) |
| POST | `/oauth/token` | Token exchange and refresh |

## API keys

Register API keys for service-to-service auth without the OAuth flow.

```go
// With a prefix to distinguish from OAuth tokens.
srv := mcpauth.New(mcpauth.Config{
	ServerURL:    "https://example.com",
	APIKeyPrefix: "sk_",
})
srv.RegisterAPIKey("sk_live_abc123", "service-account")

// Without a prefix. Tokens are speculatively checked as API keys
// and fall through to OAuth validation if not found.
srv := mcpauth.New(mcpauth.Config{
	ServerURL: "https://example.com",
})
srv.RegisterAPIKey("abc123", "service-account")

// Register by pre-computed hash when you don't have the raw key.
srv.RegisterAPIKeyByHash(mcpauth.HashSecret("abc123"), "service-account")
```

## Pre-configured clients

Register server-owned OAuth clients that bypass dynamic registration.

```go
err := srv.RegisterPreConfiguredClient(&mcpauth.OAuthClient{
	ClientID:   "my-service",
	SecretHash: mcpauth.HashSecret("client-secret"),
	GrantTypes: []string{"client_credentials"},
})
if err != nil {
	// Grant type not supported by server configuration.
	log.Fatal(err)
}
```

## Storage

By default everything is in-memory. For durable storage, implement the `Persistence` interface and pass it via `Config.Persist`.

```go
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
```

Raw secrets (tokens, refresh tokens) are never passed to the persistence layer. Only hashes are stored.

## User authentication

Implement `UserAuthenticator` for custom credential validation (LDAP, database, etc.).

```go
type UserAuthenticator interface {
	ValidateCredentials(ctx context.Context, username, password string) (userID string, err error)
}
```

`MapAuthenticator` is a built-in implementation backed by a username/password map. Passwords are hashed at construction time and not retained.

```go
users := mcpauth.NewMapAuthenticator(map[string]string{
	"alice": "password123",
	"bob":   "hunter2",
})
```

Optionally implement `UserAccountChecker` on the same type to enable per-request account validation in the middleware (disable users without revoking tokens).

## Context helpers

After the middleware authenticates a request, extract identity from the context:

```go
userID   := mcpauth.RequestUserID(r.Context())
clientID := mcpauth.RequestClientID(r.Context())
ip       := mcpauth.RequestRemoteIP(r.Context())
```

`WithUserID` injects a user ID into a context for testing:

```go
ctx := mcpauth.WithUserID(context.Background(), "test-user")
```

## License

Apache 2.0
