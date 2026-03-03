# Workarounds from vault-sync migration

Friction points discovered while migrating vault-sync from its internal auth package to mcp-auth.

## 1. No built-in MapAuthenticator

mcp-auth requires a `UserAuthenticator` interface, but many apps just have a `map[string]string` of usernames to passwords. vault-sync had to write a 20-line adapter struct to bridge the gap.

Consider shipping a `MapAuthenticator` convenience type that wraps `map[string]string` with SHA-256 constant-time comparison.

## 2. GrantTypes default excludes client_credentials

`Config.GrantTypes` defaults to `["authorization_code", "refresh_token"]`. Apps using `client_credentials` must remember to add it explicitly or the server metadata silently stops advertising it.

Given that the library fully supports `client_credentials`, consider including it in the default or requiring explicit opt-in with a loud error when a pre-configured client is registered but the grant type is not in the list.

## 3. APIKeyPrefix has no default and fails silently

When `Config.APIKeyPrefix` is empty, API key authentication is disabled. If you register API keys via `RegisterAPIKey` but forget to set the prefix, keys are treated as OAuth bearer tokens and silently fail validation.

Consider logging a warning when `RegisterAPIKey` is called with an empty `APIKeyPrefix`, or requiring the prefix to be set before keys can be registered.

## 4. LoginTitle and LoginSubtitle defaults differ from common usage

The defaults ("Sign In" / "Sign in to grant access to your account.") are generic. Apps migrating from a custom login page must explicitly set both to preserve their existing text.

Not a bug, but worth noting in migration docs.

# Workarounds from conduit migration

Friction points discovered while migrating conduit from its internal auth package to mcp-auth.

## 5. WrapMiddleware needed to resolve user ID to full user object

mcp-auth sets a string user ID in context via `RequestUserID`. Conduit's MCP server expects `*models.User` via `auth.UserFromContext`. Had to write a middleware wrapper that does a second DB lookup per request to resolve the string ID to a full user struct. Every consumer with a richer user model will need equivalent glue.

Consider adding a `Config.UserResolver` callback (e.g. `func(ctx context.Context, userID string) (context.Context, error)`) that the middleware calls after token validation, letting callers inject their own context values directly.

## 6. authServerAdapter needed due to circular dependency

mcp-auth's `RegisterPreConfiguredClient` takes `*mcpauth.OAuthClient`, but conduit's admin package cannot import mcp-auth without creating a circular dependency. Had to create an adapter struct in `cmd/conduit/main.go` that converts `admin.AuthClient` to `mcpauth.OAuthClient` at the wiring layer.

Consider accepting an interface or a plain struct without pointer in `RegisterPreConfiguredClient` so consumers can define their own compatible type without importing the mcp-auth package directly.

## 7. No way to register pre-hashed API keys

`RegisterAPIKey` takes a raw key and hashes it internally. Conduit stores legacy API keys as SHA-256 hashes and does not have the raw keys. These keys cannot be re-registered at startup. Accepted as a breaking change.

Consider adding `RegisterAPIKeyByHash(hash, userID string)` for consumers migrating from systems that already store hashed keys.

## 8. No exported context setter for testing

The `ctxUserID` context key is unexported. Tests for `WrapMiddleware` cannot inject a user ID into context directly and must spin up a real `mcpauth.Server` with a registered API key to exercise the code path. This makes unit tests heavier than necessary.

Consider exporting a `WithUserID(ctx, id) context.Context` helper or a `TestContextWithUserID` function behind a test-only file.

## 9. Redirect URI rejects http://localhost

mcp-auth's `validateRedirectScheme` only allows `https://` or `http://127.0.0.1`, rejecting `http://localhost`. Conduit's old implementation allowed localhost. Had to update e2e tests to use `127.0.0.1` instead.

Correct per RFC 8252 Section 8.3, but a behavior difference that will trip up consumers migrating from more permissive implementations.

## 10. NewSQLitePersistence startup cost

`NewSQLitePersistence` loads all persisted tokens, clients, and API keys into memory on creation. This added enough latency to break an existing 200ms integration test timeout. Bumped to 2s.

Consider lazy-loading or documenting the expected startup cost so consumers can size their timeouts appropriately.
