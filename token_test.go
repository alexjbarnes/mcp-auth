package mcpauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Additional tests for token.go edge cases

func TestToken_MethodNotAllowed(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestToken_JSONRequest(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "authcode123",
		ClientID:      clientID,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	body := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "authcode123",
		"redirect_uri":  "https://example.com/callback",
		"code_verifier": verifier,
		"client_id":     clientID,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestToken_InvalidJSONRequest(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", errResp["error"])
}

func TestToken_UnsupportedMediaType(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("data"))
	req.Header.Set("Content-Type", "text/plain")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestToken_BasicAuthPrecedesFormParams(t *testing.T) {
	s := testStore(t)
	registerPreConfiguredClient(t, s, "client1", "secret123")
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "wrong-client")
	form.Set("client_secret", "wrong-secret")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client1", "secret123")

	rec := httptest.NewRecorder()

	handler(rec, req)

	// Should succeed with basic auth credentials
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestToken_EmptyGrantType(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "unsupported_grant_type", errResp["error"])
}

func TestToken_ClientLockoutAfterFailedAuth(t *testing.T) {
	s := testStore(t)
	registerPreConfiguredClient(t, s, "client1", "secret123")
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	// Trigger lockout with failed attempts from different IPs to avoid IP rate limiting
	for i := 0; i < lockoutThreshold; i++ {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", "client1")
		form.Set("client_secret", "wrong-secret")

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Use different IP for each request to avoid IP rate limiting
		req.RemoteAddr = "1.2.3." + string(rune(i+4)) + ":1234"

		rec := httptest.NewRecorder()
		handler(rec, req)
	}

	// Next request should be locked out
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "client1")
	form.Set("client_secret", "secret123") // Correct secret

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.99:1234"

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "slow_down", errResp["error"])
	assert.Contains(t, errResp["error_description"], "repeated failures")
}

func TestToken_IPRateLimitAfterFailures(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	// Trigger IP rate limit
	for i := 0; i < tokenRateLimitMaxFail; i++ {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", "unknown")
		form.Set("client_secret", "unknown")

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "1.2.3.4:5678"

		rec := httptest.NewRecorder()
		handler(rec, req)
	}

	// Next request from same IP should be rate limited
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "test")
	form.Set("client_secret", "test")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:5678"

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "slow_down", errResp["error"])
}

func TestToken_ClientNotAuthorizedForGrant(t *testing.T) {
	s := testStore(t)

	// Register client with only authorization_code grant
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "auth-only",
		SecretHash: HashSecret("secret123"),
		GrantTypes: []string{"authorization_code"},
	})

	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	// Try to use client_credentials grant
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "auth-only")
	form.Set("client_secret", "secret123")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "unauthorized_client", errResp["error"])
}

// --- Refresh token tests ---

func TestToken_RefreshToken_MissingToken(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", errResp["error"])
}

func TestToken_RefreshToken_InvalidToken(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "invalid-token")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp["error"])
}

func TestToken_RefreshToken_ConfidentialClientMissingSecret(t *testing.T) {
	s := testStore(t)

	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "confidential",
		SecretHash: HashSecret("secret123"),
		GrantTypes: []string{"authorization_code", "refresh_token"},
	})

	refreshToken := RandomHex(32)
	s.SaveToken(&OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "user1",
		ClientID:  "confidential",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", "confidential")
	// No client_secret provided

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_client", errResp["error"])
}

func TestToken_RefreshToken_DeletesOldAccessToken(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	refreshToken := RandomHex(32)
	accessToken := "old-access-token"

	// Save access token with refresh token
	s.SaveToken(&OAuthToken{
		Token:        accessToken,
		Kind:         "access",
		UserID:       "user1",
		ClientID:     clientID,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	// Save refresh token
	s.SaveToken(&OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "user1",
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Old access token should be invalid
	assert.Nil(t, s.ValidateToken(accessToken))
}

// --- Client credentials tests ---

func TestToken_ClientCredentials_MissingClientID(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_secret", "secret123")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", errResp["error"])
}

func TestToken_ClientCredentials_MissingSecret(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "client1")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_ClientCredentials_InvalidSecret(t *testing.T) {
	s := testStore(t)
	registerPreConfiguredClient(t, s, "client1", "secret123")
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "client1")
	form.Set("client_secret", "wrong-secret")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestToken_ClientCredentials_WrongResource(t *testing.T) {
	s := testStore(t)
	registerPreConfiguredClient(t, s, "client1", "secret123")
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "client1")
	form.Set("client_secret", "secret123")
	form.Set("resource", "https://evil.com")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_target", errResp["error"])
}

func TestToken_ClientCredentials_NoRefreshToken(t *testing.T) {
	s := testStore(t)
	registerPreConfiguredClient(t, s, "client1", "secret123")
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "client1")
	form.Set("client_secret", "secret123")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken) // No refresh token for client_credentials
}

// --- Authorization code tests ---

func TestToken_AuthCode_MissingCode(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", "test-verifier")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", errResp["error"])
}

func TestToken_AuthCode_CodeReplay(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "authcode123",
		ClientID:      clientID,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode123")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)

	// First request succeeds
	req1 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec1 := httptest.NewRecorder()
	handler(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Second request (replay) should fail
	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	handler(rec2, req2)
	assert.Equal(t, http.StatusBadRequest, rec2.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec2.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Contains(t, errResp["error_description"], "already used")
}

func TestToken_AuthCode_ClientIDMismatch(t *testing.T) {
	s := testStore(t)
	clientID1 := registerTestClient(t, s, []string{"https://example.com/callback"})
	clientID2 := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	// Issue code for client1
	s.SaveCode(&Code{
		Code:          "authcode123",
		ClientID:      clientID1,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	// Try to use with client2
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode123")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID2)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Contains(t, errResp["error_description"], "mismatch")
}

func TestToken_AuthCode_RedirectURIMismatch(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{
		"https://example.com/callback1",
		"https://example.com/callback2",
	})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	// Issue code for callback1
	s.SaveCode(&Code{
		Code:          "authcode123",
		ClientID:      clientID,
		RedirectURI:   "https://example.com/callback1",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	// Try to exchange with callback2
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode123")
	form.Set("redirect_uri", "https://example.com/callback2")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Contains(t, errResp["error_description"], "redirect_uri")
}

func TestToken_CacheControlHeaders(t *testing.T) {
	s := testStore(t)
	registerPreConfiguredClient(t, s, "client1", "secret123")
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "client1")
	form.Set("client_secret", "secret123")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}