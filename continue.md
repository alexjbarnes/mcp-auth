# Continuation: workarounds.md improvements

Implement the following improvements from workarounds.md. Each item includes the exact file, method signature, and behavior.

Run `golangci-lint run` after all changes. Fix any issues. Then run `go test -race -count=1 ./...` and confirm all tests pass.

## 1. MapAuthenticator convenience type

**File:** `helpers.go`

Add a `MapAuthenticator` type that wraps `map[string]string` (username to password) and implements `UserAuthenticator`. Use SHA-256 constant-time comparison for password validation. The map key is the username, the map value is the plaintext password. Return the username as the userID on success. Import `"context"` in helpers.go. The `dummyHash` constant is already in store.go and accessible within the package. Do a dummy comparison on unknown users to prevent timing-based user enumeration.

Then remove the `testUsers` type from `store_test.go` (lines 57-64) and replace all its uses with `MapAuthenticator`. It appears in `store_test.go` and `handler_test.go`. Search for `testUsers` to find all references.

**Tests:** Add to `store_test.go`:
- `TestMapAuthenticator_ValidCredentials` - correct username/password returns userID
- `TestMapAuthenticator_WrongPassword` - correct username, wrong password returns ""
- `TestMapAuthenticator_UnknownUser` - unknown username returns ""
- `TestMapAuthenticator_EmptyMap` - empty map returns ""

## 2. APIKeyPrefix warning

**File:** `auth.go`, method `RegisterAPIKey` (line 185)

Add a check: if `srv.apiKeyPrefix == ""`, log a warning before delegating to the store. Same for `RegisterAPIKeyByHash` (item 3).

**Tests:** Verify the behavior works without panicking. Log verification is optional.

## 3. RegisterAPIKeyByHash

**File:** `store.go`

Add `RegisterAPIKeyByHash(hash, userID string)` that stores an API key using a pre-computed hash. Same logic as `RegisterAPIKey` but skips hashing.

**File:** `auth.go`

Expose as `srv.RegisterAPIKeyByHash(hash, userID string)` on Server. Include the same APIKeyPrefix warning as item 2.

**Tests:** Add to `store_test.go`:
- `TestStore_RegisterAPIKeyByHash` - register by hash, verify it exists via direct hash lookup
- `TestStore_RegisterAPIKeyByHash_WithPersist` - verify it persists

## 4. WithUserID context helper

**File:** `middleware.go`

Add `WithUserID(ctx context.Context, userID string) context.Context` that returns a context with the user ID set. Primarily for testing.

**Tests:** Add to `middleware_test.go`:
- `TestWithUserID_RoundTrip` - set a userID, retrieve it with `RequestUserID`
- `TestWithUserID_Empty` - set empty string, retrieve it

## 5. GrantTypes mismatch warning

**File:** `auth.go`, method `RegisterPreConfiguredClient` (line 171)

After delegating to the store, check whether the client's grant types include `client_credentials` but the server's `grantTypes` list does not. Log a warning if mismatched.

**Tests:** Verify the registration still works. Log verification is optional.

## Order of implementation

1, 4, 3, 2, 5

## What NOT to implement

Items 4/LoginTitle, 5/UserResolver, 6/circular dep, 9/localhost, 10/startup cost from workarounds.md. These are documentation-only or need design discussion.
