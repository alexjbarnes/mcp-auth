package mcpauth

import (
	"bytes"
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

// Metadata tests

func TestProtectedResourceMetadata(t *testing.T) {
	handler := handleProtectedResourceMetadata(testServerURL)
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=3600", rec.Header().Get("Cache-Control"))

	var meta ProtectedResourceMetadata

	err := json.NewDecoder(rec.Body).Decode(&meta)
	require.NoError(t, err)
	assert.Equal(t, testServerURL, meta.Resource)
	assert.Contains(t, meta.AuthorizationServers, testServerURL)
}

func TestServerMetadata(t *testing.T) {
	handler := handleServerMetadata(testServerURL, nil)
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var meta ServerMetadata

	err := json.NewDecoder(rec.Body).Decode(&meta)
	require.NoError(t, err)
	assert.Equal(t, testServerURL, meta.Issuer)
	assert.Equal(t, testServerURL+"/oauth/authorize", meta.AuthorizationEndpoint)
	assert.Equal(t, testServerURL+"/oauth/token", meta.TokenEndpoint)
	assert.Contains(t, meta.CodeChallengeMethodsSupported, "S256")
}

func TestMetadata_MethodNotAllowed(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{
			name:    "protected resource POST",
			handler: handleProtectedResourceMetadata(testServerURL),
			path:    "/.well-known/oauth-protected-resource",
		},
		{
			name:    "server metadata POST",
			handler: handleServerMetadata(testServerURL, nil),
			path:    "/.well-known/oauth-authorization-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tt.path, nil)
			rec := httptest.NewRecorder()
			tt.handler(rec, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}

func TestMetadata_CacheControl(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name:    "protected resource",
			handler: handleProtectedResourceMetadata(testServerURL),
		},
		{
			name:    "server metadata",
			handler: handleServerMetadata(testServerURL, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			rec := httptest.NewRecorder()
			tt.handler(rec, req)
			assert.Equal(t, "public, max-age=3600", rec.Header().Get("Cache-Control"))
		})
	}
}

func TestMetadata_IncludesClientCredentials(t *testing.T) {
	handler := handleServerMetadata(testServerURL, []string{"authorization_code", "refresh_token", "client_credentials"})
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	var meta ServerMetadata

	err := json.NewDecoder(rec.Body).Decode(&meta)
	require.NoError(t, err)
	assert.Contains(t, meta.GrantTypesSupported, "client_credentials")
}

func TestMetadata_IncludesBasicAuth(t *testing.T) {
	handler := handleServerMetadata(testServerURL, nil)
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	var meta ServerMetadata

	err := json.NewDecoder(rec.Body).Decode(&meta)
	require.NoError(t, err)
	assert.Contains(t, meta.TokenEndpointAuthMethodsSupported, "client_secret_basic")
}

func TestServerMetadata_RefreshTokenGrant(t *testing.T) {
	handler := handleServerMetadata(testServerURL, nil)
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	var meta ServerMetadata

	err := json.NewDecoder(rec.Body).Decode(&meta)
	require.NoError(t, err)
	assert.Contains(t, meta.GrantTypesSupported, "refresh_token")
}

// Registration tests

func TestRegistration_Success(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"https://example.com/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp registrationResponse

	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ClientID)
	assert.Equal(t, "Test Client", resp.ClientName)
	assert.Equal(t, []string{"https://example.com/callback"}, resp.RedirectURIs)

	// Verify client is stored
	client := s.GetClient(resp.ClientID)
	require.NotNil(t, client)
	assert.Equal(t, resp.ClientID, client.ClientID)
}

func TestRegistration_MissingRedirectURIs(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name": "Test Client",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_ClientCredentials_UsesClientUserID(t *testing.T) {
	s := testStore(t)
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "cc-with-user",
		SecretHash: HashSecret("secret123"),
		GrantTypes: []string{"client_credentials"},
		UserID:     "app-user-42",
	})

	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "cc-with-user")
	form.Set("client_secret", "secret123")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotEmpty(t, resp.AccessToken)

	tok := s.ValidateToken(resp.AccessToken)
	require.NotNil(t, tok)
	assert.Equal(t, "app-user-42", tok.UserID)
	assert.Equal(t, "cc-with-user", tok.ClientID)
}

func TestToken_ClientCredentials_FallsBackToClientID(t *testing.T) {
	s := testStore(t)
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "cc-no-user",
		SecretHash: HashSecret("secret123"),
		GrantTypes: []string{"client_credentials"},
	})

	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "cc-no-user")
	form.Set("client_secret", "secret123")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	tok := s.ValidateToken(resp.AccessToken)
	require.NotNil(t, tok)
	assert.Equal(t, "cc-no-user", tok.UserID)
}

func TestToken_ClientCredentials_DisabledUser(t *testing.T) {
	s := testStore(t)
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "cc-disabled-user",
		SecretHash: HashSecret("secret123"),
		GrantTypes: []string{"client_credentials"},
		UserID:     "disabled-user",
	})

	checker := &testAccountChecker{
		testUsers: testUsers{"disabled-user": "pass"},
		disabled:  map[string]bool{"disabled-user": true},
	}

	handler := handleToken(s, testLogger(), testServerURL, "", checker)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "cc-disabled-user")
	form.Set("client_secret", "secret123")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Contains(t, errResp["error_description"], "disabled")
}

func TestToken_ClientCredentials_ActiveUser(t *testing.T) {
	s := testStore(t)
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "cc-active-user",
		SecretHash: HashSecret("secret123"),
		GrantTypes: []string{"client_credentials"},
		UserID:     "active-user",
	})

	checker := &testAccountChecker{
		testUsers: testUsers{"active-user": "pass"},
		disabled:  map[string]bool{},
	}

	handler := handleToken(s, testLogger(), testServerURL, "", checker)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "cc-active-user")
	form.Set("client_secret", "secret123")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_Register_Helper(t *testing.T) {
	srv := New(Config{
		ServerURL: testServerURL,
		Users:     testUsers{"u": "p"},
	})
	t.Cleanup(srv.Stop)

	mux := http.NewServeMux()
	srv.Register(mux)

	tests := []struct {
		method string
		path   string
		expect int
	}{
		{"GET", "/.well-known/oauth-protected-resource", http.StatusOK},
		{"GET", "/.well-known/oauth-authorization-server", http.StatusOK},
		{"POST", "/oauth/register", http.StatusBadRequest},
		{"GET", "/oauth/authorize", http.StatusBadRequest},
		{"POST", "/oauth/token", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, tt.expect, rec.Code)
		})
	}
}

func TestToken_AuthCodeExchange_ActiveUser(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	checker := &testAccountChecker{
		testUsers: testUsers{"testuser": "pass"},
		disabled:  map[string]bool{},
	}

	handler := handleToken(s, testLogger(), testServerURL, "", checker)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "code-active-user",
		ClientID:      clientID,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "code-active-user")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestToken_RefreshToken_DisabledUser(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	checker := &testAccountChecker{
		testUsers: testUsers{"testuser": "pass"},
		disabled:  map[string]bool{"testuser": true},
	}

	handler := handleToken(s, testLogger(), testServerURL, "", checker)

	refreshToken := RandomHex(32)
	s.SaveToken(&OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		ClientID:  clientID,
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "invalid_grant", errResp["error"])
	assert.Contains(t, errResp["error_description"], "disabled")
}

func TestToken_RefreshToken_ActiveUser(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	checker := &testAccountChecker{
		testUsers: testUsers{"testuser": "pass"},
		disabled:  map[string]bool{},
	}

	handler := handleToken(s, testLogger(), testServerURL, "", checker)

	refreshToken := RandomHex(32)
	s.SaveToken(&OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		ClientID:  clientID,
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestToken_AuthCodeExchange_NoCheckerSkipsCheck(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	// Pass nil users (no account checker) — exchange should succeed.
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "code-no-checker",
		ClientID:      clientID,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "code-no-checker")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestToken_AuthCodeExchange_PlainUsersNoChecker(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	// Pass a plain UserAuthenticator (not UserAccountChecker) — check is skipped.
	users := testUsers{"testuser": "pass"}
	handler := handleToken(s, testLogger(), testServerURL, "", users)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "code-plain-users",
		ClientID:      clientID,
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "code-plain-users")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- Auth code replay detection at token endpoint ---

func TestToken_AuthCodeReplayRevokesTokens(t *testing.T) {
	s := testStore(t)
	s.RegisterClient(&OAuthClient{ClientID: "client1", RedirectURIs: []string{"https://example.com/callback"}})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "replay-code",
		ClientID:      "client1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	// First exchange succeeds.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"replay-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"client1"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	accessToken := resp.AccessToken
	require.NotEmpty(t, accessToken)

	// Verify the token is valid.
	assert.NotNil(t, s.ValidateToken(accessToken))

	// Second exchange with the same code triggers replay detection.
	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()
	handler(rec2, req2)

	assert.Equal(t, http.StatusBadRequest, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "already used")

	// The token from the first exchange should now be revoked.
	assert.Nil(t, s.ValidateToken(accessToken))
}

func TestToken_AuthCodeReplayWrongClientNoRevoke(t *testing.T) {
	s := testStore(t)
	s.RegisterClient(&OAuthClient{ClientID: "client1", RedirectURIs: []string{"https://example.com/callback"}})
	s.RegisterClient(&OAuthClient{ClientID: "attacker", RedirectURIs: []string{"https://example.com/callback"}})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "bound-code",
		ClientID:      "client1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	// First exchange succeeds for client1.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"bound-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"client1"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	accessToken := resp.AccessToken

	// Attacker tries to replay with a different client_id.
	form.Set("client_id", "attacker")
	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()
	handler(rec2, req2)

	// Replay is detected but client_id doesn't match, so tokens
	// for client1 should NOT be revoked.
	assert.Equal(t, http.StatusBadRequest, rec2.Code)
	assert.NotNil(t, s.ValidateToken(accessToken))
}

func TestRegistration_ClientLimitReached(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	// Fill up the client limit
	for i := 0; i < maxClients; i++ {
		s.RegisterClient(&OAuthClient{
			ClientID:     RandomHex(16),
			RedirectURIs: []string{"https://example.com/callback"},
		})
	}

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestRegistration_RejectsHTTPRedirectURI(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"http://attacker.com/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegistration_AllowsHTTPLoopback(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"http://127.0.0.1:8080/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestRegistration_RejectsHTTPLocalhost(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"http://localhost:8080/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegistration_RejectsImplicitGrant(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"implicit"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not available through dynamic registration")
}

func TestRegistration_RejectsPasswordGrant(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"password"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegistration_BlocksClientCredentials(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"client_credentials"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegistration_BlocksClientCredentialsMixed(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"authorization_code", "client_credentials"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegistration_StoresGrantTypes(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	client := s.GetClient(resp.ClientID)
	require.NotNil(t, client)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, client.GrantTypes)
}

func TestRegistration_AllowsRefreshTokenGrant(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestRegistration_ConfidentialClientGetsSecret(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris":              []string{"https://example.com/callback"},
		"token_endpoint_auth_method": "client_secret_post",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.ClientSecret)
}

func TestRegistration_PublicClientNoSecret(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris":              []string{"https://example.com/callback"},
		"token_endpoint_auth_method": "none",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Empty(t, resp.ClientSecret)
}

func TestRegistration_ClientIDIssuedAt(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Positive(t, resp.ClientIDIssuedAt)
}

func TestRegistration_PersistsResponseTypesAndAuthMethod(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris":              []string{"https://example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.ResponseTypes)
	assert.Equal(t, "client_secret_basic", resp.TokenEndpointAuthMethod)
}

func TestRegistration_RejectsWrongContentType(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "text/plain")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestRegistration_AcceptsNoContentType(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	// No Content-Type header
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestRegistration_ClientSecretExpiresAt(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris":              []string{"https://example.com/callback"},
		"token_endpoint_auth_method": "client_secret_post",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.ClientSecretExpiresAt)
	assert.Equal(t, int64(0), *resp.ClientSecretExpiresAt)
}

func TestRegistration_NoSecretExpiresAt_WhenAuthMethodNone(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"redirect_uris":              []string{"https://example.com/callback"},
		"token_endpoint_auth_method": "none",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Nil(t, resp.ClientSecretExpiresAt)
}

// Authorize GET tests

func TestAuthorize_GET_ShowsLoginForm(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://example.com/callback&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "username")
	assert.Contains(t, rec.Body.String(), "password")
}

func TestAuthorize_GET_MissingClientID(t *testing.T) {
	s := testStore(t)
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&redirect_uri=https://example.com/callback", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_GET_UnknownClient(t *testing.T) {
	s := testStore(t)
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=unknown&redirect_uri=https://example.com/callback&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_GET_InvalidRedirectURI(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://attacker.com/callback&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_GET_MissingPKCE(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://example.com/callback", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
}

func TestAuthorize_GET_MissingResponseType(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id="+clientID+"&redirect_uri=https://example.com/callback&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
}

func TestAuthorize_GET_WrongResponseType(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=token&client_id="+clientID+"&redirect_uri=https://example.com/callback&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=unsupported_response_type")
}

func TestAuthorize_GET_ClickjackHeaders(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://example.com/callback&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "frame-ancestors 'none'", rec.Header().Get("Content-Security-Policy"))
}

func TestAuthorize_GET_ResourceParameter(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://example.com/callback&code_challenge="+challenge+"&resource="+url.QueryEscape(testServerURL), nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthorize_GET_WrongResource(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://example.com/callback&code_challenge="+challenge+"&resource=https://wrong.example.com", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
}

func TestAuthorize_GET_LoopbackPrefixRedirect(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"http://127.0.0.1"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=http://127.0.0.1:12345/callback&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// Authorize POST tests

func TestAuthorize_POST_ValidLogin(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "iss="+url.QueryEscape(testServerURL))
}

func TestAuthorize_POST_ScopeNotPropagatedToCode(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("scope", "read write admin")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	u, err := url.Parse(location)
	require.NoError(t, err)

	code := u.Query().Get("code")
	require.NotEmpty(t, code)

	// Scopes from the form should NOT be propagated to the code.
	retrievedCode, _ := s.ConsumeCode(code)
	require.NotNil(t, retrievedCode)
	assert.Nil(t, retrievedCode.Scopes, "scopes should not be propagated from authorize form to code")
}

func TestAuthorize_POST_StateURLEncoded(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")
	state := "has&equals=and spaces"

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("state", state)

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	location := rec.Header().Get("Location")
	u, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, state, u.Query().Get("state"))
}

func TestAuthorize_POST_RedirectURIWithQueryParams(t *testing.T) {
	s := testStore(t)
	redirectURI := "https://example.com/callback?existing=param"
	clientID := registerTestClient(t, s, []string{redirectURI})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, redirectURI)
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	location := rec.Header().Get("Location")
	u, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, "param", u.Query().Get("existing"))
	assert.NotEmpty(t, u.Query().Get("code"))
}

func TestAuthorize_POST_InvalidPassword(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "wrongpassword")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid username or password")
}

func TestAuthorize_POST_InvalidRedirectURI(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://attacker.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_POST_MissingCSRF(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestAuthorize_POST_MissingPKCE(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
}

func TestAuthorize_POST_RateLimited(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")

	for i := 0; i < 11; i++ {
		csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")

		form := url.Values{}
		form.Set("client_id", clientID)
		form.Set("redirect_uri", "https://example.com/callback")
		form.Set("code_challenge", challenge)
		form.Set("csrf_token", csrfToken)
		form.Set("username", "testuser")
		form.Set("password", "wrongpassword")

		req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()

		handler(rec, req)

		if i < 10 {
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		}
	}
}

func TestAuthorize_POST_IssInResponse(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	location := rec.Header().Get("Location")
	u, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, testServerURL, u.Query().Get("iss"))
}

func TestAuthorize_POST_ResourceBindsToCode(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("resource", testServerURL)

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	location := rec.Header().Get("Location")
	u, err := url.Parse(location)
	require.NoError(t, err)

	code := u.Query().Get("code")

	// Verify code has resource bound
	retrievedCode, _ := s.ConsumeCode(code)
	require.NotNil(t, retrievedCode)
	assert.Equal(t, testServerURL, retrievedCode.Resource)
}

// Token tests (auth code flow)

func TestToken_FullFlow(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var resp tokenResponse

	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestToken_InvalidCode(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "invalid")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", "test-verifier")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_WrongGrantType(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "magic")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_PKCEVerificationFails(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	challenge := pkceChallenge("correct-verifier")

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
	form.Set("code_verifier", "wrong-verifier")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_MissingPKCE(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	challenge := pkceChallenge("test-verifier")

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
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_NoPKCEOnCode(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	s.SaveCode(&Code{
		Code:        "authcode123",
		ClientID:    clientID,
		RedirectURI: "https://example.com/callback",
		UserID:      "testuser",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode123")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", "test-verifier")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_RedirectURIMismatch(t *testing.T) {
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
	form.Set("redirect_uri", "https://attacker.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_AuthCodeClientIDMismatch(t *testing.T) {
	s := testStore(t)
	clientID1 := registerTestClient(t, s, []string{"https://example.com/callback"})
	clientID2 := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "authcode123",
		ClientID:      clientID1,
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
	form.Set("client_id", clientID2)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_JSONBody(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestToken_FullFlowWithRefresh(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	refreshToken := resp.RefreshToken

	// Use refresh token
	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", refreshToken)
	form2.Set("client_id", clientID)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	assert.Equal(t, http.StatusOK, rec2.Code)

	var resp2 tokenResponse
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&resp2))
	assert.NotEmpty(t, resp2.AccessToken)
	assert.NotEmpty(t, resp2.RefreshToken)
}

func TestToken_ResourceParameter(t *testing.T) {
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
		Resource:      testServerURL,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode123")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)
	form.Set("resource", testServerURL)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestToken_WrongResourceParameter(t *testing.T) {
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
		Resource:      testServerURL,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode123")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)
	form.Set("resource", "https://wrong.example.com")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_ScopeInResponse(t *testing.T) {
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
		Scopes:        []string{"read", "write"},
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode123")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "read write", resp.Scope)
}

func TestToken_PragmaNoCache(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}

// Token tests (refresh)

func TestToken_RefreshGrant(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", resp.RefreshToken)
	form2.Set("client_id", clientID)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	assert.Equal(t, http.StatusOK, rec2.Code)
}

func TestToken_RefreshRotation(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	oldRefreshToken := resp.RefreshToken

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", oldRefreshToken)
	form2.Set("client_id", clientID)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	var resp2 tokenResponse
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&resp2))
	newRefreshToken := resp2.RefreshToken

	assert.NotEqual(t, oldRefreshToken, newRefreshToken)

	// Old refresh token should be consumed
	form3 := url.Values{}
	form3.Set("grant_type", "refresh_token")
	form3.Set("refresh_token", oldRefreshToken)
	form3.Set("client_id", clientID)

	req3 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec3 := httptest.NewRecorder()

	handler(rec3, req3)

	assert.Equal(t, http.StatusBadRequest, rec3.Code)
}

func TestToken_RefreshExpired(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	s.SaveToken(&OAuthToken{
		Token:     "expired-refresh",
		Kind:      "refresh",
		UserID:    "testuser",
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		ClientID:  clientID,
	})

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "expired-refresh")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_RefreshWrongClient(t *testing.T) {
	s := testStore(t)
	clientID1 := registerTestClient(t, s, []string{"https://example.com/callback"})
	clientID2 := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	s.SaveCode(&Code{
		Code:          "authcode123",
		ClientID:      clientID1,
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
	form.Set("client_id", clientID1)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", resp.RefreshToken)
	form2.Set("client_id", clientID2)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	assert.Equal(t, http.StatusBadRequest, rec2.Code)
}

func TestToken_RefreshWrongResource(t *testing.T) {
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
		Resource:      testServerURL,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode123")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)
	form.Set("resource", testServerURL)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", resp.RefreshToken)
	form2.Set("client_id", clientID)
	form2.Set("resource", "https://wrong.example.com")

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	assert.Equal(t, http.StatusBadRequest, rec2.Code)
}

func TestToken_RefreshMissingToken(t *testing.T) {
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
}

func TestToken_RefreshWithoutClientID(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", resp.RefreshToken)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	assert.Equal(t, http.StatusBadRequest, rec2.Code)
}

func TestToken_RefreshDeletesOldAccessToken(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	oldAccessToken := resp.AccessToken
	refreshToken := resp.RefreshToken

	// Verify old access token works
	ti := s.ValidateToken(oldAccessToken)
	require.NotNil(t, ti)

	// Use refresh token
	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", refreshToken)
	form2.Set("client_id", clientID)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	// Old access token should be invalid
	ti = s.ValidateToken(oldAccessToken)
	assert.Nil(t, ti)
}

func TestToken_AccessTokenUsedAsRefresh(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", resp.AccessToken)
	form2.Set("client_id", clientID)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	assert.Equal(t, http.StatusBadRequest, rec2.Code)
}

func TestToken_RefreshTokenReuseFails(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	refreshToken := resp.RefreshToken

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", refreshToken)
	form2.Set("client_id", clientID)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	assert.Equal(t, http.StatusOK, rec2.Code)

	// Try to reuse the same refresh token
	req3 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec3 := httptest.NewRecorder()

	handler(rec3, req3)

	assert.Equal(t, http.StatusBadRequest, rec3.Code)
}

// Token tests (client credentials)

func TestClientCredentials_Success(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken)
}

func TestClientCredentials_WrongSecret(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", "wrong-secret")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestClientCredentials_MissingSecret(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestClientCredentials_MissingClientID(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_secret", "secret")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestClientCredentials_UnknownClient(t *testing.T) {
	s := testStore(t)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "unknown")
	form.Set("client_secret", "secret")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestClientCredentials_DynamicClientCannotUse(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", "secret")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestClientCredentials_WithResource(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	form.Set("resource", testServerURL)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClientCredentials_WrongResource(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	form.Set("resource", "https://wrong.example.com")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestClientCredentials_JSONBody(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	body := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": secret,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClientCredentials_JSONBodyWithCharset(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	body := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": secret,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClientCredentials_TokenUsableAsBearer(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	tokenHandler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	tokenHandler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// Use token in middleware
	middleware := authMiddleware(s, testLogger(), testServerURL, "", "", nil)
	protectedHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req2 := httptest.NewRequest("GET", "/protected", nil)
	req2.Header.Set("Authorization", "Bearer "+resp.AccessToken)

	rec2 := httptest.NewRecorder()

	protectedHandler.ServeHTTP(rec2, req2)

	assert.Equal(t, http.StatusOK, rec2.Code)
}

func TestClientCredentials_NoRefreshToken(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Empty(t, resp.RefreshToken)
}

func TestClientCredentials_BasicAuth(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClientCredentials_BasicAuthOverridesBody(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "wrong-id")
	form.Set("client_secret", "wrong-secret")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClientCredentials_BasicAuthWrongPassword(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "wrong-secret")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// Token tests (grant type enforcement)

func TestToken_GrantTypeEnforcement(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", "secret")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestToken_DefaultGrantTypeAllowsAuthCode(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestToken_RefreshAlwaysAllowed(t *testing.T) {
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", resp.RefreshToken)
	form2.Set("client_id", clientID)

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()

	handler(rec2, req2)

	assert.Equal(t, http.StatusOK, rec2.Code)
}

// Token tests (rate limiting)

func TestToken_IPRateLimit(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	for i := 0; i < 6; i++ {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", "invalid")
		form.Set("redirect_uri", "https://example.com/callback")
		form.Set("code_verifier", "test-verifier")
		form.Set("client_id", clientID)

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()

		handler(rec, req)

		switch {
		case i < 5:
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		default:
			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		}
	}
}

func TestToken_ClientLockout(t *testing.T) {
	s := testStore(t)
	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})
	handler := handleToken(s, testLogger(), testServerURL, "", nil)

	for i := 0; i < 11; i++ {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", "invalid")
		form.Set("redirect_uri", "https://example.com/callback")
		form.Set("code_verifier", "test-verifier")
		form.Set("client_id", clientID)

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()

		handler(rec, req)

		switch {
		case i < 5:
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		default:
			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		}
	}
}

// Pre-configured client tests

func TestPreConfigured_AuthorizeEndpointRejected(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)

	users := testUsers{"testuser": "password123"}
	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "Sign in to grant access to your account.", "", nil)

	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://example.com/callback&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPreConfigured_AuthCodeFlowRejected(t *testing.T) {
	s := testStore(t)
	clientID := "preconfigured-client"
	secret := "super-secret"
	registerPreConfiguredClient(t, s, clientID, secret)
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

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
