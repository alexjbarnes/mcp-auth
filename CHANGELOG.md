# Changelog

## v0.2.1

### Bug fixes

- Reject authorization requests where `code_challenge_method` is missing. The server only supports S256, but an omitted method defaults to `plain` per RFC 7636, which silently passed authorization then failed at token exchange with a confusing `invalid_grant` error.

## v0.2.0

### Breaking changes

- Dynamic client registration now defaults `token_endpoint_auth_method` to `client_secret_basic` per RFC 7591 (was `none`). Clients that need public registration must explicitly set `token_endpoint_auth_method` to `none` in their registration request.
- Refresh token grants are now subject to `grant_types` enforcement. Clients must include `refresh_token` in their registered grant types. Clients registered without explicit grant types default to `["authorization_code", "refresh_token"]` for backward compatibility.

### Security fixes

- Use rightmost IP from proxy header (`X-Forwarded-For`) to prevent rate limit bypass via client-controlled leftmost entries.
- Enforce path matching in loopback redirect URI validation per RFC 8252. Previously only scheme and hostname were compared, allowing any path when loopback matching was used.
- Authenticate confidential clients during authorization code and refresh token exchanges. Previously clients with a `secret_hash` were not required to present their secret.
- Validate refresh token before authenticating the client in the refresh flow, preventing information leakage about whether a client is confidential.
- Combine client lookup and secret validation into a single lock acquisition (`AuthenticateConfidentialClient`), eliminating a TOCTOU race where the client could be modified between the two calls.
- Preserve partial failure counts during rate limiter pruning. Previously an attacker could flush a target client's failure count by flooding with dummy client IDs.
- Use timing-safe dummy comparison in `AuthenticateConfidentialClient` for unknown and public clients, consistent with `ValidateClientSecret`.
- Raw access tokens and refresh tokens are scrubbed before persistence so plaintext secrets never reach disk.

### Bug fixes

- Propagate scopes from the authorize request through to the authorization code and issued tokens.
- Normalize empty path to `/` in loopback redirect matching so `http://127.0.0.1:8080` matches `http://127.0.0.1/` and vice versa.
- Release mutex before persistence I/O in `cleanup`, `ConsumeRefreshToken`, and `RegisterClient` to avoid blocking concurrent token operations behind disk latency.
- Prevent double-close panic on `store.stop()` by wrapping channel close in `sync.Once`.

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
