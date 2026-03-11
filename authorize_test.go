package mcpauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Additional tests for authorize.go edge cases

func TestAuthorize_GET_ClientNotAllowedAuthorizationCode(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	// Register client without authorization_code grant
	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"client_credentials"},
	})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	challenge := pkceChallenge("test-verifier")
	reqURL := "/oauth/authorize?response_type=code&client_id=client1&redirect_uri=https://example.com/callback&code_challenge=" + challenge + "&code_challenge_method=S256"

	req := httptest.NewRequest("GET", reqURL, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not authorized")
}

func TestAuthorize_GET_MultipleRedirectURIsNoDefault(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID := registerTestClient(t, s, []string{
		"https://example.com/callback1",
		"https://example.com/callback2",
	})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	challenge := pkceChallenge("test-verifier")
	reqURL := "/oauth/authorize?response_type=code&client_id=" + clientID + "&code_challenge=" + challenge

	req := httptest.NewRequest("GET", reqURL, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "redirect_uri is required")
}

func TestAuthorize_GET_SingleRedirectURIAutoSelected(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	challenge := pkceChallenge("test-verifier")
	reqURL := "/oauth/authorize?response_type=code&client_id=" + clientID + "&code_challenge=" + challenge

	req := httptest.NewRequest("GET", reqURL, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "https://example.com/callback")
}

func TestAuthorize_GET_UnsupportedCodeChallengeMethod(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	reqURL := "/oauth/authorize?response_type=code&client_id=" + clientID + "&redirect_uri=https://example.com/callback&code_challenge=test&code_challenge_method=plain"

	req := httptest.NewRequest("GET", reqURL, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
	assert.Contains(t, location, "S256")
}

func TestAuthorize_POST_MultipleRedirectURIsNoDefault(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID := registerTestClient(t, s, []string{
		"https://example.com/callback1",
		"https://example.com/callback2",
	})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback1")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	// No redirect_uri provided
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "redirect_uri is required")
}

func TestAuthorize_POST_UnknownClient(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", "unknown-client")
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", "fake-csrf")
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unknown client_id")
}

func TestAuthorize_POST_WrongCSRFClientID(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID1 := registerTestClient(t, s, []string{"https://example.com/callback"})
	clientID2 := registerTestClient(t, s, []string{"https://example.com/callback"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	// Get CSRF token for client1
	csrfToken := getCSRFToken(t, handler, clientID1, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	// Try to use it with client2
	form := url.Values{}
	form.Set("client_id", clientID2)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "CSRF")
}

func TestAuthorize_POST_WrongCSRFRedirectURI(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID := registerTestClient(t, s, []string{
		"https://example.com/callback1",
		"https://example.com/callback2",
	})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	// Get CSRF token for callback1
	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback1")
	challenge := pkceChallenge("test-verifier")

	// Try to use it with callback2
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback2")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "CSRF")
}

func TestAuthorize_POST_InvalidFormData(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	// Send invalid form data (not properly encoded)
	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader("%ZZ%ZZ"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid form data")
}

func TestAuthorize_POST_EmptyUsername(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid username or password")
}

func TestAuthorize_POST_EmptyPassword(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid username or password")
}

func TestAuthorize_MethodNotAllowed(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	req := httptest.NewRequest("PUT", "/oauth/authorize", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAuthorize_POST_WrongResource(t *testing.T) {
	s := testStore(t)
	users := NewMapAuthenticator(map[string]string{"testuser": "password123"})

	clientID := registerTestClient(t, s, []string{"https://example.com/callback"})

	handler := handleAuthorize(s, users, testLogger(), testServerURL, "Sign In", "", "", nil)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://example.com/callback")
	form.Set("code_challenge", challenge)
	form.Set("csrf_token", csrfToken)
	form.Set("username", "testuser")
	form.Set("password", "password123")
	form.Set("resource", "https://evil.com")

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
	assert.Contains(t, location, "resource")
}

func TestGenerateCSRFToken_Length(t *testing.T) {
	s := testStore(t)
	token := generateCSRFToken(s, "client1", "https://example.com/callback")

	// Should be hex-encoded with csrfTokenBytes (16) * 2 = 32 chars
	assert.Len(t, token, 32)
}

func TestGenerateCSRFToken_Unique(t *testing.T) {
	s := testStore(t)

	token1 := generateCSRFToken(s, "client1", "https://example.com/callback")
	token2 := generateCSRFToken(s, "client1", "https://example.com/callback")

	assert.NotEqual(t, token1, token2)
}

func TestGenerateCSRFToken_Stored(t *testing.T) {
	s := testStore(t)

	token := generateCSRFToken(s, "client1", "https://example.com/callback")

	// Should be consumable
	ok := s.ConsumeCSRF(token, "client1", "https://example.com/callback")
	assert.True(t, ok)
}