# Changelog

## v0.1.0

### Features

- OAuth 2.1 authorization server with PKCE (RFC 7636)
- Authorization server metadata (RFC 8414)
- Protected resource metadata (RFC 9728)
- Dynamic client registration (RFC 7591)
- Authorization code and client credentials grant types
- Refresh token rotation
- API key authentication with optional prefix
- Pre-configured client registration with grant type validation
- Register API keys by raw key or pre-computed hash
- Pluggable storage via `Persistence` interface (in-memory by default)
- Pluggable user authentication via `UserAuthenticator` interface
- `MapAuthenticator` built-in implementation (hashes passwords at construction, no plaintext retained)
- Optional `UserAccountChecker` for per-request account validation
- `WithUserID` context helper for testing
- Custom login page template support
- Pluggable client secret validation (bcrypt, argon2, etc.)
- Rate limiting on token endpoint and login attempts
- Auth code replay detection with token revocation
- Client and API key reconciliation for config-driven deployments
- `Register(mux)` helper to wire all endpoints in one call
- CI pipeline with golangci-lint, race-detected tests, and coverage badge
