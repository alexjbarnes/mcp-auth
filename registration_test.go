package mcpauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Additional tests for registration.go edge cases

func TestRegistration_MethodNotAllowed(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	req := httptest.NewRequest("GET", "/oauth/register", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestRegistration_InvalidContentType(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := `{"client_name":"Test","redirect_uris":["https://example.com/callback"]}`

	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_client_metadata", errResp["error"])
}

func TestRegistration_InvalidJSON(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegistration_EmptyRedirectURIs(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_client_metadata", errResp["error"])
}

func TestRegistration_InvalidRedirectScheme(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"http://example.com/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_redirect_uri", errResp["error"])
	assert.Contains(t, errResp["error_description"], "HTTPS")
}

func TestRegistration_LoopbackRedirectAllowed(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"http://127.0.0.1/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestRegistration_DisallowedGrantType(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"password"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_client_metadata", errResp["error"])
	assert.Contains(t, errResp["error_description"], "password")
}

func TestRegistration_AllowedGrantTypes(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
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
	assert.ElementsMatch(t, []string{"authorization_code", "refresh_token"}, resp.GrantTypes)
}

func TestRegistration_DefaultGrantTypes(t *testing.T) {
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
	assert.Equal(t, []string{"authorization_code"}, resp.GrantTypes)
}

func TestRegistration_DefaultResponseTypes(t *testing.T) {
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
	assert.Equal(t, []string{"code"}, resp.ResponseTypes)
}

func TestRegistration_UnsupportedAuthMethod(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":                  "Test Client",
		"redirect_uris":                []string{"https://example.com/callback"},
		"token_endpoint_auth_method":   "private_key_jwt",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_client_metadata", errResp["error"])
	assert.Contains(t, errResp["error_description"], "private_key_jwt")
}

func TestRegistration_AuthMethodNone(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":                  "Test Client",
		"redirect_uris":                []string{"https://example.com/callback"},
		"token_endpoint_auth_method":   "none",
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
	assert.Equal(t, "none", resp.TokenEndpointAuthMethod)
	assert.Empty(t, resp.ClientSecret)
	assert.Nil(t, resp.ClientSecretExpiresAt)
}

func TestRegistration_AuthMethodClientSecretPost(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":                  "Test Client",
		"redirect_uris":                []string{"https://example.com/callback"},
		"token_endpoint_auth_method":   "client_secret_post",
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
	assert.Equal(t, "client_secret_post", resp.TokenEndpointAuthMethod)
	assert.NotEmpty(t, resp.ClientSecret)
	assert.NotNil(t, resp.ClientSecretExpiresAt)
	assert.Equal(t, int64(0), *resp.ClientSecretExpiresAt)
}

func TestRegistration_AuthMethodClientSecretBasic(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "")

	body := map[string]interface{}{
		"client_name":                  "Test Client",
		"redirect_uris":                []string{"https://example.com/callback"},
		"token_endpoint_auth_method":   "client_secret_basic",
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
	assert.Equal(t, "client_secret_basic", resp.TokenEndpointAuthMethod)
	assert.NotEmpty(t, resp.ClientSecret)
}

func TestRegistration_DefaultAuthMethod(t *testing.T) {
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
	assert.Equal(t, "client_secret_basic", resp.TokenEndpointAuthMethod)
	assert.NotEmpty(t, resp.ClientSecret)
}

func TestRegistration_ClientIDIssuedAtSet(t *testing.T) {
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
	assert.NotZero(t, resp.ClientIDIssuedAt)
}

func TestRegistration_MaxClientsReached(t *testing.T) {
	s := testStore(t)

	// Fill up to max clients
	for i := 0; i < maxClients; i++ {
		s.RegisterClient(&OAuthClient{
			ClientID:     RandomHex(16),
			RedirectURIs: []string{"https://example.com/callback"},
		})
	}

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

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "server_error", errResp["error"])
	assert.Contains(t, errResp["error_description"], "maximum")
}

func TestRegistration_RateLimitExceeded(t *testing.T) {
	s := testStore(t)

	// Exhaust rate limit
	for i := 0; i < maxRegistrationsPerMinute; i++ {
		ok := s.RegistrationAllowed()
		require.True(t, ok)
	}

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

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "rate_limit", errResp["error"])
}

func TestRegistration_CacheControlHeader(t *testing.T) {
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
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestRegistration_TrustedProxyHeader(t *testing.T) {
	s := testStore(t)
	handler := handleRegistration(s, testLogger(), "X-Forwarded-For")

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"https://example.com/callback"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/oauth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req.RemoteAddr = "10.0.0.1:1234"

	rec := httptest.NewRecorder()

	handler(rec, req)

	// Should succeed regardless of IP (just testing header is processed)
	assert.Equal(t, http.StatusCreated, rec.Code)
}