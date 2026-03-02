package mcpauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shared test helpers

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func testStore(t *testing.T) *store {
	t.Helper()

	s := newStore(nil, testLogger(), nil)
	t.Cleanup(s.stop)

	return s
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func registerTestClient(t *testing.T, s *store, redirectURIs []string) string {
	t.Helper()

	clientID := RandomHex(16)
	ok := s.RegisterClient(&OAuthClient{
		ClientID:     clientID,
		RedirectURIs: redirectURIs,
	})
	require.True(t, ok)

	return clientID
}

func registerPreConfiguredClient(t *testing.T, s *store, clientID, secret string) {
	t.Helper()
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   clientID,
		SecretHash: HashSecret(secret),
		GrantTypes: []string{"client_credentials"},
	})
}

const testServerURL = "https://vault.example.com"

func getCSRFToken(t *testing.T, handler http.HandlerFunc, clientID, redirectURI string) string {
	t.Helper()

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri="+url.QueryEscape(redirectURI)+"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	re := regexp.MustCompile(`name="csrf_token" value="([a-f0-9]+)"`)
	matches := re.FindStringSubmatch(rec.Body.String())
	require.Len(t, matches, 2, "CSRF token not found in form")

	return matches[1]
}

// Mock persistence for testing

type mockPersist struct {
	tokens  map[string]OAuthToken
	clients map[string]OAuthClient
	apiKeys map[string]APIKey
}

func newMockPersist() *mockPersist {
	return &mockPersist{
		tokens:  make(map[string]OAuthToken),
		clients: make(map[string]OAuthClient),
		apiKeys: make(map[string]APIKey),
	}
}

func (m *mockPersist) SaveOAuthToken(t OAuthToken) error {
	m.tokens[t.TokenHash] = t
	return nil
}

func (m *mockPersist) DeleteOAuthToken(hash string) error {
	delete(m.tokens, hash)
	return nil
}

func (m *mockPersist) AllOAuthTokens() ([]OAuthToken, error) {
	var out []OAuthToken
	for _, t := range m.tokens {
		out = append(out, t)
	}

	return out, nil
}

func (m *mockPersist) SaveOAuthClient(c OAuthClient) error {
	m.clients[c.ClientID] = c
	return nil
}

func (m *mockPersist) DeleteOAuthClient(id string) error {
	delete(m.clients, id)
	return nil
}

func (m *mockPersist) AllOAuthClients() ([]OAuthClient, error) {
	var out []OAuthClient
	for _, c := range m.clients {
		out = append(out, c)
	}

	return out, nil
}

func (m *mockPersist) SaveAPIKey(hash string, k APIKey) error {
	m.apiKeys[hash] = k
	return nil
}

func (m *mockPersist) DeleteAPIKey(hash string) error {
	delete(m.apiKeys, hash)
	return nil
}

func (m *mockPersist) AllAPIKeys() (map[string]APIKey, error) {
	out := make(map[string]APIKey, len(m.apiKeys))
	for k, v := range m.apiKeys {
		out[k] = v
	}

	return out, nil
}

// Store tests

func TestStore_CodeRoundTrip(t *testing.T) {
	s := testStore(t)
	code := &Code{
		Code:        "test-code",
		ClientID:    "client1",
		RedirectURI: "https://example.com/callback",
		UserID:      "user1",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	s.SaveCode(code)

	retrieved, replayed := s.ConsumeCode("test-code")
	require.NotNil(t, retrieved)
	assert.False(t, replayed)
	assert.Equal(t, "test-code", retrieved.Code)
	assert.Equal(t, "user1", retrieved.UserID)

	// Second consume returns replay.
	retrieved, replayed = s.ConsumeCode("test-code")
	require.NotNil(t, retrieved)
	assert.True(t, replayed)
}

func TestStore_CodeExpired(t *testing.T) {
	s := testStore(t)
	code := &Code{
		Code:      "expired-code",
		ClientID:  "client1",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}

	s.SaveCode(code)

	retrieved, _ := s.ConsumeCode("expired-code")
	assert.Nil(t, retrieved)
}

func TestStore_CodeNotFound(t *testing.T) {
	s := testStore(t)
	retrieved, _ := s.ConsumeCode("nonexistent")
	assert.Nil(t, retrieved)
}

func TestStore_TokenRoundTrip(t *testing.T) {
	s := testStore(t)
	token := &OAuthToken{
		Token:     "test-token",
		Kind:      "access",
		UserID:    "user1",
		Resource:  "https://vault.example.com",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	retrieved := s.ValidateToken("test-token")
	require.NotNil(t, retrieved)
	assert.Equal(t, "user1", retrieved.UserID)
	assert.Equal(t, "access", retrieved.Kind)
}

func TestStore_TokenExpired(t *testing.T) {
	s := testStore(t)
	token := &OAuthToken{
		Token:     "expired-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}

	s.SaveToken(token)

	retrieved := s.ValidateToken("expired-token")
	assert.Nil(t, retrieved)
}

func TestStore_TokenNotFound(t *testing.T) {
	s := testStore(t)
	retrieved := s.ValidateToken("nonexistent")
	assert.Nil(t, retrieved)
}

func TestStore_ClientRoundTrip(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	retrieved := s.GetClient(clientID)
	require.NotNil(t, retrieved)
	assert.Equal(t, clientID, retrieved.ClientID)

	nonexistent := s.GetClient("nonexistent")
	assert.Nil(t, nonexistent)
}

func TestStore_ClientMaxLimit(t *testing.T) {
	s := testStore(t)

	// Register maxClients clients
	for i := 0; i < maxClients; i++ {
		ok := s.RegisterClient(&OAuthClient{
			ClientID:     RandomHex(16),
			RedirectURIs: []string{"https://example.com/callback"},
		})
		require.True(t, ok)
	}

	// Next registration should fail
	ok := s.RegisterClient(&OAuthClient{
		ClientID:     RandomHex(16),
		RedirectURIs: []string{"https://example.com/callback"},
	})
	assert.False(t, ok)
}

func TestStore_CSRFRoundTrip(t *testing.T) {
	s := testStore(t)
	token := RandomHex(16)
	clientID := "client1"
	redirectURI := "https://example.com/callback"

	s.SaveCSRF(token, clientID, redirectURI)

	ok := s.ConsumeCSRF(token, clientID, redirectURI)
	assert.True(t, ok)

	// Second consume should fail
	ok = s.ConsumeCSRF(token, clientID, redirectURI)
	assert.False(t, ok)
}

func TestStore_CSRFEmpty(t *testing.T) {
	s := testStore(t)
	ok := s.ConsumeCSRF("", "client1", "https://example.com/callback")
	assert.False(t, ok)
}

func TestStore_CSRFNotFound(t *testing.T) {
	s := testStore(t)
	ok := s.ConsumeCSRF("nonexistent", "client1", "https://example.com/callback")
	assert.False(t, ok)
}

func TestStore_CSRFWrongBinding(t *testing.T) {
	s := testStore(t)
	token := RandomHex(16)

	s.SaveCSRF(token, "client1", "https://example.com/callback")

	ok := s.ConsumeCSRF(token, "client2", "https://example.com/callback")
	assert.False(t, ok)
}

func TestStore_CSRFWrongRedirect(t *testing.T) {
	s := testStore(t)
	token := RandomHex(16)

	s.SaveCSRF(token, "client1", "https://example.com/callback")

	ok := s.ConsumeCSRF(token, "client1", "https://different.com/callback")
	assert.False(t, ok)
}

func TestStore_Cleanup(t *testing.T) {
	s := testStore(t)

	// Add expired code
	s.SaveCode(&Code{
		Code:      "expired-code",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})

	// Add expired token
	expiredToken := &OAuthToken{
		Token:     "expired-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	s.SaveToken(expiredToken)

	// Add expired CSRF
	s.SaveCSRF(RandomHex(16), "client1", "https://example.com/callback")
	s.mu.Lock()
	for k, entry := range s.csrf {
		entry.expiresAt = time.Now().Add(-1 * time.Minute)
		s.csrf[k] = entry
	}
	s.mu.Unlock()

	// Add valid code
	s.SaveCode(&Code{
		Code:      "valid-code",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	// Add valid token
	validToken := &OAuthToken{
		Token:     "valid-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	s.SaveToken(validToken)

	s.cleanup()

	s.mu.RLock()
	defer s.mu.RUnlock()

	assert.NotContains(t, s.codes, "expired-code")
	assert.Contains(t, s.codes, "valid-code")
	assert.NotContains(t, s.tokens, HashSecret("expired-token"))
	assert.Contains(t, s.tokens, HashSecret("valid-token"))
}

func TestStore_ValidateClientSecret(t *testing.T) {
	s := testStore(t)
	secret := "my-secret"
	registerPreConfiguredClient(t, s, "client1", secret)

	ok := s.ValidateClientSecret("client1", secret)
	assert.True(t, ok)

	ok = s.ValidateClientSecret("client1", "wrong-secret")
	assert.False(t, ok)
}

func TestStore_ValidateClientSecret_NoHash(t *testing.T) {
	s := testStore(t)

	// Client with no secret hash
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "client1",
		GrantTypes: []string{"client_credentials"},
	})

	// Should fail with any secret (uses dummy hash for timing-safe comparison)
	ok := s.ValidateClientSecret("client1", "any-secret")
	assert.False(t, ok)
}

func TestStore_RegisterAndValidateAPIKey(t *testing.T) {
	s := testStore(t)
	rawKey := RandomHex(32)

	s.RegisterAPIKey(rawKey, "user1")

	retrieved := s.ValidateAPIKey(rawKey)
	require.NotNil(t, retrieved)
	assert.Equal(t, "user1", retrieved.UserID)
}

func TestStore_ValidateAPIKey_Unknown(t *testing.T) {
	s := testStore(t)
	retrieved := s.ValidateAPIKey("unknown-key")
	assert.Nil(t, retrieved)
}

func TestStore_ValidateAPIKey_WrongKey(t *testing.T) {
	s := testStore(t)
	s.RegisterAPIKey(RandomHex(32), "user1")

	retrieved := s.ValidateAPIKey(RandomHex(32))
	assert.Nil(t, retrieved)
}

func TestStore_RevokeAPIKey(t *testing.T) {
	s := testStore(t)
	rawKey := RandomHex(32)
	s.RegisterAPIKey(rawKey, "user1")

	keyHash := HashSecret(rawKey)
	s.RevokeAPIKey(keyHash)

	retrieved := s.ValidateAPIKey(rawKey)
	assert.Nil(t, retrieved)
}

func TestStore_ListAPIKeys(t *testing.T) {
	s := testStore(t)

	s.RegisterAPIKey(RandomHex(32), "user1")
	s.RegisterAPIKey(RandomHex(32), "user2")
	s.RegisterAPIKey(RandomHex(32), "user3")

	keys := s.ListAPIKeys()
	assert.Len(t, keys, 3)
}

func TestStore_RegisterAPIKey_OverwritesSameKey(t *testing.T) {
	s := testStore(t)
	rawKey := RandomHex(32)

	s.RegisterAPIKey(rawKey, "user1")
	s.RegisterAPIKey(rawKey, "user2")

	keys := s.ListAPIKeys()
	assert.Len(t, keys, 1)
	assert.Equal(t, "user2", keys[0].UserID)
}

func TestStore_ReconcileAPIKeys_RemovesStaleKeys(t *testing.T) {
	s := testStore(t)

	key1 := RandomHex(32)
	key2 := RandomHex(32)
	key3 := RandomHex(32)

	s.RegisterAPIKey(key1, "user1")
	s.RegisterAPIKey(key2, "user2")
	s.RegisterAPIKey(key3, "user3")

	hash1 := HashSecret(key1)
	hash3 := HashSecret(key3)

	current := map[string]struct{}{
		hash1: {},
		hash3: {},
	}

	removed := s.ReconcileAPIKeys(current)
	assert.Equal(t, 1, removed)

	keys := s.ListAPIKeys()
	assert.Len(t, keys, 2)
}

func TestStore_ReconcileAPIKeys_KeepsAllCurrent(t *testing.T) {
	s := testStore(t)

	key1 := RandomHex(32)
	key2 := RandomHex(32)

	s.RegisterAPIKey(key1, "user1")
	s.RegisterAPIKey(key2, "user2")

	hash1 := HashSecret(key1)
	hash2 := HashSecret(key2)

	current := map[string]struct{}{
		hash1: {},
		hash2: {},
	}

	removed := s.ReconcileAPIKeys(current)
	assert.Equal(t, 0, removed)

	keys := s.ListAPIKeys()
	assert.Len(t, keys, 2)
}

func TestStore_ReconcileAPIKeys_EmptyConfigPurgesAll(t *testing.T) {
	s := testStore(t)

	s.RegisterAPIKey(RandomHex(32), "user1")
	s.RegisterAPIKey(RandomHex(32), "user2")

	removed := s.ReconcileAPIKeys(map[string]struct{}{})
	assert.Equal(t, 2, removed)

	keys := s.ListAPIKeys()
	assert.Empty(t, keys)
}

func TestStore_ReconcileClients_RemovesStale(t *testing.T) {
	s := testStore(t)

	// Register pre-configured clients with client_credentials grant
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "client1",
		GrantTypes: []string{"client_credentials"},
	})
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "client2",
		GrantTypes: []string{"client_credentials"},
	})

	current := map[string]struct{}{
		"client1": {},
	}

	removed := s.ReconcileClients(current)
	assert.Equal(t, 1, removed)

	retrieved := s.GetClient("client2")
	assert.Nil(t, retrieved)
}

func TestStore_ReconcileClients_PreservesDynamicClients(t *testing.T) {
	s := testStore(t)

	// Register dynamic client (no grant_types or authorization_code)
	s.RegisterClient(&OAuthClient{
		ClientID:     "dynamic1",
		RedirectURIs: []string{"https://example.com/callback"},
	})

	// Register pre-configured client
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "preconfigured1",
		GrantTypes: []string{"client_credentials"},
	})

	current := map[string]struct{}{
		"preconfigured1": {},
	}

	removed := s.ReconcileClients(current)
	assert.Equal(t, 0, removed)

	// Dynamic client should still exist
	retrieved := s.GetClient("dynamic1")
	assert.NotNil(t, retrieved)
}

func TestStore_ValidateRefreshToken(t *testing.T) {
	s := testStore(t)

	refreshToken := RandomHex(32)
	token := &OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	refreshHash := HashSecret(refreshToken)

	s.mu.RLock()
	retrieved := s.validateRefreshTokenLocked(refreshHash, "", "")
	s.mu.RUnlock()

	require.NotNil(t, retrieved)
	assert.Equal(t, "refresh", retrieved.Kind)
}

func TestStore_ValidateRefreshToken_RejectsAccessToken(t *testing.T) {
	s := testStore(t)

	token := &OAuthToken{
		Token:     "access-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	s.mu.RLock()

	tokenHash := HashSecret("access-token")
	retrieved := s.validateRefreshTokenLocked(tokenHash, "", "")
	s.mu.RUnlock()

	assert.Nil(t, retrieved)
}

func TestSaveToken_ComputesRefreshHash(t *testing.T) {
	s := testStore(t)

	refreshToken := RandomHex(32)
	token := &OAuthToken{
		Token:        "access-token",
		Kind:         "access",
		UserID:       "user1",
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	s.mu.RLock()
	defer s.mu.RUnlock()

	assert.NotEmpty(t, token.RefreshHash)
	assert.Equal(t, HashSecret(refreshToken), token.RefreshHash)
}

func TestSaveToken_NoRefreshHash_WhenNoRefreshToken(t *testing.T) {
	s := testStore(t)

	token := &OAuthToken{
		Token:     "access-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	assert.Empty(t, token.RefreshHash)
}

func TestRegistrationAllowed_PrunesOldEntries(t *testing.T) {
	s := testStore(t)

	// Add old entries
	s.mu.Lock()
	s.registrationTimes = append(s.registrationTimes, time.Now().Add(-2*time.Minute))
	s.registrationTimes = append(s.registrationTimes, time.Now().Add(-2*time.Minute))
	s.mu.Unlock()

	// Call RegistrationAllowed multiple times
	for i := 0; i < 5; i++ {
		ok := s.RegistrationAllowed()
		assert.True(t, ok)
	}

	s.mu.RLock()
	// Old entries should be pruned
	for _, regTime := range s.registrationTimes {
		assert.True(t, time.Now().Add(-1*time.Minute).Before(regTime))
	}

	s.mu.RUnlock()
}

func TestRegistrationAllowed_SlidingWindow(t *testing.T) {
	s := testStore(t)

	// Fill up the window
	for i := 0; i < maxRegistrationsPerMinute; i++ {
		ok := s.RegistrationAllowed()
		assert.True(t, ok)
	}

	// Next should be rejected
	ok := s.RegistrationAllowed()
	assert.False(t, ok)
}

// Helper tests

func TestRandomHex_Length(t *testing.T) {
	result := RandomHex(16)
	assert.Len(t, result, 32) // 16 bytes = 32 hex chars
}

func TestRandomHex_Unique(t *testing.T) {
	result1 := RandomHex(16)
	result2 := RandomHex(16)
	assert.NotEqual(t, result1, result2)
}

func TestRandomHex_VariousLengths(t *testing.T) {
	tests := []struct {
		byteLen int
		hexLen  int
	}{
		{1, 2},
		{8, 16},
		{32, 64},
	}

	for _, tt := range tests {
		result := RandomHex(tt.byteLen)
		assert.Len(t, result, tt.hexLen)
	}
}

func TestHashSecret_Deterministic(t *testing.T) {
	secret := "test-secret"
	hash1 := HashSecret(secret)
	hash2 := HashSecret(secret)
	assert.Equal(t, hash1, hash2)
}

func TestVerifyPKCE_Valid(t *testing.T) {
	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)
	ok := verifyPKCE(verifier, challenge)
	assert.True(t, ok)
}

func TestVerifyPKCE_Invalid(t *testing.T) {
	verifier := "test-verifier"
	challenge := pkceChallenge("different-verifier")
	ok := verifyPKCE(verifier, challenge)
	assert.False(t, ok)
}

func TestRemoteIP_WithPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	ip := remoteIP(req)
	assert.Equal(t, "1.2.3.4", ip)
}

func TestRemoteIP_WithoutPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4"
	ip := remoteIP(req)
	assert.Equal(t, "1.2.3.4", ip)
}

func TestRemoteIP_IPv6WithPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:1234"
	ip := remoteIP(req)
	assert.Equal(t, "::1", ip)
}

func TestRemoteIP_IPv6WithoutPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "::1"
	ip := remoteIP(req)
	assert.Equal(t, "::1", ip)
}

func TestIsLoopbackRedirect_InvalidRedirectURI(t *testing.T) {
	ok := isLoopbackRedirect("not a url", "http://127.0.0.1")
	assert.False(t, ok)
}

func TestIsLoopbackRedirect_InvalidRegisteredPrefix(t *testing.T) {
	ok := isLoopbackRedirect("http://127.0.0.1:8080/callback", "not a url")
	assert.False(t, ok)
}

func TestIsLoopbackRedirect_BothInvalid(t *testing.T) {
	ok := isLoopbackRedirect("not a url", "also not a url")
	// Both parse as paths with empty scheme/hostname, so they match
	assert.True(t, ok)
}

func TestIsLoopbackRedirect_ValidMatch(t *testing.T) {
	ok := isLoopbackRedirect("http://127.0.0.1:8080/callback", "http://127.0.0.1")
	assert.True(t, ok)
}

func TestIsLoopbackRedirect_SchemeMismatch(t *testing.T) {
	ok := isLoopbackRedirect("https://127.0.0.1:8080/callback", "http://127.0.0.1")
	assert.False(t, ok)
}

func TestIsLoopbackHost_RejectsLocalhost(t *testing.T) {
	ok := isLoopbackHost("localhost")
	assert.False(t, ok)
}

func TestValidateRedirectURI_NoRegisteredURIs_RejectsLocalhost(t *testing.T) {
	client := &OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{},
	}

	ok := validateRedirectURI(client, "http://localhost:8080/callback")
	assert.False(t, ok)
}

// Rate limiter tests

func TestCheckLockout_EmptyClientID(t *testing.T) {
	limiter := newTokenRateLimiter()
	ok := limiter.checkLockout("")
	assert.False(t, ok)
}

func TestCheckLockout_NoEntry(t *testing.T) {
	limiter := newTokenRateLimiter()
	ok := limiter.checkLockout("client1")
	assert.False(t, ok)
}

func TestCheckLockout_SubThresholdEntry(t *testing.T) {
	limiter := newTokenRateLimiter()

	for i := 0; i < lockoutThreshold-1; i++ {
		limiter.recordFailure("1.2.3.4", "client1")
	}

	ok := limiter.checkLockout("client1")
	assert.False(t, ok)
}

func TestCheckLockout_ActiveLockout(t *testing.T) {
	limiter := newTokenRateLimiter()

	for i := 0; i < lockoutThreshold; i++ {
		limiter.recordFailure("1.2.3.4", "client1")
	}

	ok := limiter.checkLockout("client1")
	assert.True(t, ok)
}

func TestCheckLockout_ExpiredLockoutResets(t *testing.T) {
	limiter := newTokenRateLimiter()

	for i := 0; i < lockoutThreshold; i++ {
		limiter.recordFailure("1.2.3.4", "client1")
	}

	// Manually expire the lockout
	limiter.mu.Lock()
	entry := limiter.lockouts["client1"]
	entry.lockedAt = time.Now().Add(-lockoutDuration - 1*time.Minute)
	limiter.mu.Unlock()

	ok := limiter.checkLockout("client1")
	assert.False(t, ok)

	// Entry should be cleaned up
	limiter.mu.Lock()
	_, exists := limiter.lockouts["client1"]
	limiter.mu.Unlock()
	assert.False(t, exists)
}

func TestCheckLockout_PrunesStaleEntries(t *testing.T) {
	limiter := newTokenRateLimiter()

	// Add many stale entries
	limiter.mu.Lock()
	for i := 0; i < tokenLimiterPruneThreshold+100; i++ {
		clientID := "client" + string(rune(i))
		entry := &lockoutEntry{
			failures: 1,
			lockedAt: time.Now().Add(-lockoutDuration - 1*time.Minute),
		}
		limiter.lockouts[clientID] = entry
	}
	limiter.mu.Unlock()

	// Trigger pruning by checking a lockout
	limiter.checkLockout("client1")

	limiter.mu.Lock()
	count := len(limiter.lockouts)
	limiter.mu.Unlock()

	// Should have pruned stale entries
	assert.Less(t, count, tokenLimiterPruneThreshold+100)
}

func TestCheckLockout_PruneKeepsActiveLockouts(t *testing.T) {
	limiter := newTokenRateLimiter()

	// Add active lockout
	limiter.mu.Lock()
	limiter.lockouts["active"] = &lockoutEntry{
		failures: lockoutThreshold,
		lockedAt: time.Now(),
	}

	// Add stale lockout
	limiter.lockouts["stale"] = &lockoutEntry{
		failures: 1,
		lockedAt: time.Now().Add(-lockoutDuration - 1*time.Minute),
	}

	// Fill to trigger pruning
	for i := 0; i < tokenLimiterPruneThreshold+100; i++ {
		clientID := "client" + string(rune(i))
		limiter.lockouts[clientID] = &lockoutEntry{
			failures: 1,
			lockedAt: time.Now().Add(-lockoutDuration - 1*time.Minute),
		}
	}
	limiter.mu.Unlock()

	limiter.checkLockout("active")

	limiter.mu.Lock()
	_, activeExists := limiter.lockouts["active"]
	_, staleExists := limiter.lockouts["stale"]
	limiter.mu.Unlock()

	assert.True(t, activeExists)
	assert.False(t, staleExists)
}

// Persistence tests

func TestLoadFromDisk_TokensClientsAPIKeys(t *testing.T) {
	persist := newMockPersist()

	// Save data via mock persist
	token := OAuthToken{
		TokenHash: HashSecret("token1"),
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, persist.SaveOAuthToken(token))

	client := OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{"https://example.com/callback"},
	}
	require.NoError(t, persist.SaveOAuthClient(client))

	apiKey := APIKey{
		KeyHash:   HashSecret("key1"),
		UserID:    "user1",
		CreatedAt: time.Now(),
	}
	require.NoError(t, persist.SaveAPIKey(HashSecret("key1"), apiKey))

	// Create new store with persist
	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	// Verify loaded
	s.mu.RLock()
	assert.Len(t, s.tokens, 1)
	assert.Len(t, s.clients, 1)
	assert.Len(t, s.apiKeys, 1)
	s.mu.RUnlock()
}

func TestLoadFromDisk_ExpiredTokensDeleted(t *testing.T) {
	persist := newMockPersist()

	// Save expired token
	token := OAuthToken{
		TokenHash: HashSecret("expired"),
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	require.NoError(t, persist.SaveOAuthToken(token))

	// Create new store
	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	// Verify not loaded
	s.mu.RLock()
	assert.Empty(t, s.tokens)
	s.mu.RUnlock()

	// Verify deleted from persist
	tokens, _ := persist.AllOAuthTokens()
	assert.Empty(t, tokens)
}

func TestLoadFromDisk_EmptyTokenHashSkipped(t *testing.T) {
	persist := newMockPersist()

	// Save token with empty hash
	token := OAuthToken{
		TokenHash: "",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, persist.SaveOAuthToken(token))

	// Create new store
	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	// Verify not loaded
	s.mu.RLock()
	assert.Empty(t, s.tokens)
	s.mu.RUnlock()
}

func TestLoadFromDisk_RefreshHashBackwardCompat(t *testing.T) {
	persist := newMockPersist()

	// Save access token with RefreshToken but no RefreshHash
	refreshToken := RandomHex(32)
	token := OAuthToken{
		TokenHash:    HashSecret("token1"),
		Kind:         "access",
		UserID:       "user1",
		RefreshToken: refreshToken,
		RefreshHash:  "",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, persist.SaveOAuthToken(token))

	// Create new store
	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	// Verify RefreshHash was computed
	s.mu.RLock()
	savedToken := s.tokens[HashSecret("token1")]
	s.mu.RUnlock()

	require.NotNil(t, savedToken)
	assert.Equal(t, HashSecret(refreshToken), savedToken.RefreshHash)
}

func TestLoadFromDisk_MigratesLegacyTokens(t *testing.T) {
	persist := newMockPersist()

	// Save token with Token set but TokenHash empty
	token := OAuthToken{
		Token:     "legacy-token",
		TokenHash: "",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, persist.SaveOAuthToken(token))

	// Create new store
	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	// Verify loaded with computed hash
	s.mu.RLock()
	assert.Len(t, s.tokens, 1)
	savedToken := s.tokens[HashSecret("legacy-token")]
	s.mu.RUnlock()

	require.NotNil(t, savedToken)
	assert.Equal(t, HashSecret("legacy-token"), savedToken.TokenHash)
}

func TestRegisterPreConfiguredClient_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "client1",
		GrantTypes: []string{"client_credentials"},
	})

	clients, _ := persist.AllOAuthClients()
	assert.Len(t, clients, 1)
	assert.Equal(t, "client1", clients[0].ClientID)
}

func TestRegisterClient_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	s.RegisterClient(&OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{"https://example.com/callback"},
	})

	clients, _ := persist.AllOAuthClients()
	assert.Len(t, clients, 1)
	assert.Equal(t, "client1", clients[0].ClientID)
}

func TestRegisterAPIKey_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	rawKey := RandomHex(32)
	s.RegisterAPIKey(rawKey, "user1")

	keys, _ := persist.AllAPIKeys()
	assert.Len(t, keys, 1)
}

func TestRevokeAPIKey_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	rawKey := RandomHex(32)
	s.RegisterAPIKey(rawKey, "user1")

	keyHash := HashSecret(rawKey)
	s.RevokeAPIKey(keyHash)

	keys, _ := persist.AllAPIKeys()
	assert.Empty(t, keys)
}

func TestReconcileAPIKeys_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	key1 := RandomHex(32)
	key2 := RandomHex(32)

	s.RegisterAPIKey(key1, "user1")
	s.RegisterAPIKey(key2, "user2")

	hash1 := HashSecret(key1)
	current := map[string]struct{}{
		hash1: {},
	}

	s.ReconcileAPIKeys(current)

	keys, _ := persist.AllAPIKeys()
	assert.Len(t, keys, 1)
}

func TestSaveToken_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	token := &OAuthToken{
		Token:     "test-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	tokens, _ := persist.AllOAuthTokens()
	assert.Len(t, tokens, 1)
}

func TestCleanup_WithPersist_DeletesExpiredTokens(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	token := &OAuthToken{
		Token:     "expired-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}

	s.SaveToken(token)

	s.cleanup()

	tokens, _ := persist.AllOAuthTokens()
	assert.Empty(t, tokens)
}

func TestDeleteToken_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	refreshToken := RandomHex(32)
	token := &OAuthToken{
		Token:        "access-token",
		Kind:         "access",
		UserID:       "user1",
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	s.DeleteAccessTokenByRefreshToken(refreshToken)

	tokens, _ := persist.AllOAuthTokens()
	assert.Empty(t, tokens)
}

func TestConsumeRefreshToken_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	refreshToken := RandomHex(32)
	token := &OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	s.ConsumeRefreshToken(refreshToken, "", "")

	tokens, _ := persist.AllOAuthTokens()
	assert.Empty(t, tokens)
}

func TestDeleteAccessTokenByRefreshToken_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	refreshToken := RandomHex(32)
	token := &OAuthToken{
		Token:        "access-token",
		Kind:         "access",
		UserID:       "user1",
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	s.SaveToken(token)

	s.DeleteAccessTokenByRefreshToken(refreshToken)

	tokens, _ := persist.AllOAuthTokens()
	assert.Empty(t, tokens)
}

func TestStore_ReconcileClients_WithPersist(t *testing.T) {
	persist := newMockPersist()

	s := newStore(persist, testLogger(), nil)
	defer s.stop()

	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "client1",
		GrantTypes: []string{"client_credentials"},
	})
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "client2",
		GrantTypes: []string{"client_credentials"},
	})

	current := map[string]struct{}{
		"client1": {},
	}

	s.ReconcileClients(current)

	clients, _ := persist.AllOAuthClients()
	assert.Len(t, clients, 1)
	assert.Equal(t, "client1", clients[0].ClientID)
}

// --- resourceMatches same-origin tests ---

func TestResourceMatches_ExactMatch(t *testing.T) {
	assert.True(t, resourceMatches("https://example.com", "https://example.com"))
}

func TestResourceMatches_TrailingSlash(t *testing.T) {
	assert.True(t, resourceMatches("https://example.com/", "https://example.com"))
	assert.True(t, resourceMatches("https://example.com", "https://example.com/"))
}

func TestResourceMatches_SameOriginDifferentPath(t *testing.T) {
	assert.True(t, resourceMatches("https://example.com/mcp", "https://example.com"))
	assert.True(t, resourceMatches("https://example.com/api/v1", "https://example.com"))
}

func TestResourceMatches_DifferentHost(t *testing.T) {
	assert.False(t, resourceMatches("https://evil.com/mcp", "https://example.com"))
}

func TestResourceMatches_DifferentScheme(t *testing.T) {
	assert.False(t, resourceMatches("http://example.com/mcp", "https://example.com"))
}

func TestResourceMatches_DifferentPort(t *testing.T) {
	assert.False(t, resourceMatches("https://example.com:8443/mcp", "https://example.com"))
}

func TestResourceMatches_InvalidURL(t *testing.T) {
	assert.False(t, resourceMatches("://invalid", "https://example.com"))
}

// --- Auth code replay detection tests ---

func TestStore_CodeReplayDetected(t *testing.T) {
	s := testStore(t)
	s.SaveCode(&Code{
		Code:      "replay-code",
		ClientID:  "client1",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	// First consumption succeeds.
	ac, replayed := s.ConsumeCode("replay-code")
	require.NotNil(t, ac)
	assert.False(t, replayed)
	assert.Equal(t, "client1", ac.ClientID)

	// Second consumption detects replay.
	ac, replayed = s.ConsumeCode("replay-code")
	require.NotNil(t, ac)
	assert.True(t, replayed)
	assert.Equal(t, "client1", ac.ClientID)
}

func TestStore_CodeReplayExpired(t *testing.T) {
	s := testStore(t)
	s.SaveCode(&Code{
		Code:      "expired-replay",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})

	// Expired code returns nil even if never consumed.
	ac, replayed := s.ConsumeCode("expired-replay")
	assert.Nil(t, ac)
	assert.False(t, replayed)
}

func TestStore_RevokeClientTokens(t *testing.T) {
	s := testStore(t)

	// Issue tokens for two different clients.
	s.SaveToken(&OAuthToken{
		Token:     "access-c1",
		Kind:      "access",
		UserID:    "user1",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	s.SaveToken(&OAuthToken{
		Token:     "refresh-c1",
		Kind:      "refresh",
		UserID:    "user1",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	s.SaveToken(&OAuthToken{
		Token:     "access-c2",
		Kind:      "access",
		UserID:    "user2",
		ClientID:  "client2",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Revoke all tokens for client1.
	s.RevokeClientTokens("client1")

	// client1 tokens are gone.
	assert.Nil(t, s.ValidateToken("access-c1"))

	// client2 tokens are untouched.
	assert.NotNil(t, s.ValidateToken("access-c2"))
}

func TestStore_RevokeClientTokens_WithPersist(t *testing.T) {
	persist := newMockPersist()
	s := newStore(persist, testLogger(), nil)
	t.Cleanup(s.stop)

	s.SaveToken(&OAuthToken{
		Token:     "persist-tok",
		Kind:      "access",
		UserID:    "user1",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	assert.Len(t, persist.tokens, 1)

	s.RevokeClientTokens("client1")

	assert.Empty(t, persist.tokens)
}

func TestStore_RemoveClient(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	assert.NotNil(t, s.GetClient(clientID))
	assert.True(t, s.RemoveClient(clientID))
	assert.Nil(t, s.GetClient(clientID))
}

func TestStore_RemoveClient_NotFound(t *testing.T) {
	s := testStore(t)
	assert.False(t, s.RemoveClient("nonexistent"))
}

func TestStore_RemoveClient_WithPersist(t *testing.T) {
	persist := newMockPersist()
	s := newStore(persist, testLogger(), nil)
	t.Cleanup(s.stop)

	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "client-to-remove",
		GrantTypes: []string{"client_credentials"},
		SecretHash: HashSecret("secret"),
	})

	assert.Len(t, persist.clients, 1)
	assert.True(t, s.RemoveClient("client-to-remove"))
	assert.Empty(t, persist.clients)
	assert.Nil(t, s.GetClient("client-to-remove"))
}

// --- MapAuthenticator tests ---

func TestMapAuthenticator_ValidCredentials(t *testing.T) {
	m := MapAuthenticator{"alice": "secret"}
	userID, err := m.ValidateCredentials(context.Background(), "alice", "secret")
	require.NoError(t, err)
	assert.Equal(t, "alice", userID)
}

func TestMapAuthenticator_WrongPassword(t *testing.T) {
	m := MapAuthenticator{"alice": "secret"}
	userID, err := m.ValidateCredentials(context.Background(), "alice", "wrong")
	require.NoError(t, err)
	assert.Empty(t, userID)
}

func TestMapAuthenticator_UnknownUser(t *testing.T) {
	m := MapAuthenticator{"alice": "secret"}
	userID, err := m.ValidateCredentials(context.Background(), "bob", "secret")
	require.NoError(t, err)
	assert.Empty(t, userID)
}

func TestMapAuthenticator_EmptyMap(t *testing.T) {
	m := MapAuthenticator{}
	userID, err := m.ValidateCredentials(context.Background(), "alice", "secret")
	require.NoError(t, err)
	assert.Empty(t, userID)
}

// --- RegisterAPIKeyByHash tests ---

func TestStore_RegisterAPIKeyByHash(t *testing.T) {
	s := testStore(t)

	hash := HashSecret("my-api-key")
	s.RegisterAPIKeyByHash(hash, "user1")

	s.mu.RLock()
	ak := s.apiKeys[hash]
	s.mu.RUnlock()

	require.NotNil(t, ak)
	assert.Equal(t, "user1", ak.UserID)
	assert.Equal(t, hash, ak.KeyHash)
}

func TestStore_RegisterAPIKeyByHash_WithPersist(t *testing.T) {
	persist := newMockPersist()
	s := newStore(persist, testLogger(), nil)
	t.Cleanup(s.stop)

	hash := HashSecret("my-api-key")
	s.RegisterAPIKeyByHash(hash, "user1")

	keys, _ := persist.AllAPIKeys()
	assert.Len(t, keys, 1)
	assert.Equal(t, "user1", keys[hash].UserID)
}
