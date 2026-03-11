package mcpauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- MapAuthenticator tests ---

func TestMapAuthenticator_MultipleUsers(t *testing.T) {
	m := NewMapAuthenticator(map[string]string{
		"alice": "password1",
		"bob":   "password2",
		"carol": "password3",
	})

	tests := []struct {
		username string
		password string
		expected string
	}{
		{"alice", "password1", "alice"},
		{"bob", "password2", "bob"},
		{"carol", "password3", "carol"},
		{"alice", "wrong", ""},
		{"bob", "wrong", ""},
		{"unknown", "password1", ""},
		{"unknown", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.username+"_"+tt.password, func(t *testing.T) {
			userID, err := m.ValidateCredentials(context.Background(), tt.username, tt.password)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, userID)
		})
	}
}

func TestMapAuthenticator_EmptyPassword(t *testing.T) {
	m := NewMapAuthenticator(map[string]string{"user": "pass"})
	userID, err := m.ValidateCredentials(context.Background(), "user", "")
	require.NoError(t, err)
	assert.Empty(t, userID)
}

func TestMapAuthenticator_EmptyUsername(t *testing.T) {
	m := NewMapAuthenticator(map[string]string{"user": "pass"})
	userID, err := m.ValidateCredentials(context.Background(), "", "pass")
	require.NoError(t, err)
	assert.Empty(t, userID)
}

func TestMapAuthenticator_BothEmpty(t *testing.T) {
	m := NewMapAuthenticator(map[string]string{"user": "pass"})
	userID, err := m.ValidateCredentials(context.Background(), "", "")
	require.NoError(t, err)
	assert.Empty(t, userID)
}

func TestMapAuthenticator_PasswordWithSpecialChars(t *testing.T) {
	specialPass := "p@ss!w0rd#$%^&*()"
	m := NewMapAuthenticator(map[string]string{"user": specialPass})

	userID, err := m.ValidateCredentials(context.Background(), "user", specialPass)
	require.NoError(t, err)
	assert.Equal(t, "user", userID)

	userID, err = m.ValidateCredentials(context.Background(), "user", "wrong")
	require.NoError(t, err)
	assert.Empty(t, userID)
}

// --- HashSecret tests ---

func TestHashSecret_EmptyString(t *testing.T) {
	hash := HashSecret("")
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64) // SHA-256 produces 64 hex chars
}

func TestHashSecret_LongString(t *testing.T) {
	longStr := string(make([]byte, 10000))
	hash := HashSecret(longStr)
	assert.Len(t, hash, 64)
}

func TestHashSecret_Unicode(t *testing.T) {
	hash1 := HashSecret("hello世界")
	hash2 := HashSecret("hello世界")
	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 64)
}

// --- RandomHex tests ---

func TestRandomHex_ZeroLength(t *testing.T) {
	result := RandomHex(0)
	assert.Empty(t, result)
}

func TestRandomHex_LargeLength(t *testing.T) {
	result := RandomHex(256)
	assert.Len(t, result, 512)
}

func TestRandomHex_UniquenessAcrossMany(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		result := RandomHex(16)
		assert.False(t, seen[result], "duplicate random value generated")
		seen[result] = true
	}
}

// --- verifyPKCE tests ---

func TestVerifyPKCE_EmptyVerifier(t *testing.T) {
	challenge := pkceChallenge("test")
	ok := verifyPKCE("", challenge)
	assert.False(t, ok)
}

func TestVerifyPKCE_EmptyChallenge(t *testing.T) {
	ok := verifyPKCE("test", "")
	assert.False(t, ok)
}

func TestVerifyPKCE_BothEmpty(t *testing.T) {
	ok := verifyPKCE("", "")
	assert.False(t, ok)
}

func TestVerifyPKCE_LongVerifier(t *testing.T) {
	verifier := string(make([]byte, 1000))
	challenge := pkceChallenge(verifier)
	ok := verifyPKCE(verifier, challenge)
	assert.True(t, ok)
}

func TestVerifyPKCE_SpecialCharsInVerifier(t *testing.T) {
	verifier := "test-verifier_with.special~chars"
	challenge := pkceChallenge(verifier)
	ok := verifyPKCE(verifier, challenge)
	assert.True(t, ok)
}

func TestVerifyPKCE_CaseSensitive(t *testing.T) {
	verifier := "TestVerifier"
	challenge := pkceChallenge(verifier)
	ok := verifyPKCE("testverifier", challenge)
	assert.False(t, ok)
}

// --- remoteIP tests ---

func TestRemoteIP_IPv4WithHighPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:65535"
	ip := remoteIP(req)
	assert.Equal(t, "192.168.1.1", ip)
}

func TestRemoteIP_IPv6Loopback(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:8080"
	ip := remoteIP(req)
	assert.Equal(t, "::1", ip)
}

func TestRemoteIP_IPv6Full(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443"
	ip := remoteIP(req)
	assert.Equal(t, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", ip)
}

func TestRemoteIP_MalformedAddress(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "not-a-valid-address"
	ip := remoteIP(req)
	assert.Equal(t, "not-a-valid-address", ip) // Falls back to raw value
}

func TestRemoteIP_EmptyAddress(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""
	ip := remoteIP(req)
	assert.Equal(t, "", ip)
}

// --- extractIP tests ---

func TestExtractIP_NoProxyHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	ip := extractIP(req, "")
	assert.Equal(t, "1.2.3.4", ip)
}

func TestExtractIP_ProxyHeaderSingleIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	ip := extractIP(req, "X-Forwarded-For")
	assert.Equal(t, "203.0.113.50", ip)
}

func TestExtractIP_ProxyHeaderMultipleIPs(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.5, 203.0.113.50, 70.41.3.18")
	ip := extractIP(req, "X-Forwarded-For")
	assert.Equal(t, "70.41.3.18", ip) // Last IP
}

func TestExtractIP_ProxyHeaderWithSpaces(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "  203.0.113.50  ")
	ip := extractIP(req, "X-Forwarded-For")
	assert.Equal(t, "203.0.113.50", ip)
}

func TestExtractIP_ProxyHeaderEmpty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "")
	ip := extractIP(req, "X-Forwarded-For")
	assert.Equal(t, "10.0.0.1", ip) // Falls back to RemoteAddr
}

func TestExtractIP_ProxyHeaderNotPresent(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	ip := extractIP(req, "X-Forwarded-For")
	assert.Equal(t, "10.0.0.1", ip)
}

func TestExtractIP_CustomProxyHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")
	ip := extractIP(req, "CF-Connecting-IP")
	assert.Equal(t, "203.0.113.50", ip)
}

// --- resourceMatches tests ---

func TestResourceMatches_EmptyStrings(t *testing.T) {
	assert.True(t, resourceMatches("", ""))
}

func TestResourceMatches_OneEmpty(t *testing.T) {
	assert.False(t, resourceMatches("https://example.com", ""))
	assert.False(t, resourceMatches("", "https://example.com"))
}

func TestResourceMatches_SameOriginWithPort(t *testing.T) {
	assert.True(t, resourceMatches("https://example.com:8443/mcp", "https://example.com:8443"))
}

func TestResourceMatches_SubdomainDiffers(t *testing.T) {
	assert.False(t, resourceMatches("https://api.example.com/mcp", "https://example.com"))
}

func TestResourceMatches_PathDiffers(t *testing.T) {
	assert.True(t, resourceMatches("https://example.com/api/v1", "https://example.com/"))
	assert.True(t, resourceMatches("https://example.com/mcp", "https://example.com/other"))
}

func TestResourceMatches_QueryStringDiffers(t *testing.T) {
	assert.True(t, resourceMatches("https://example.com/mcp?foo=bar", "https://example.com"))
}

func TestResourceMatches_FragmentDiffers(t *testing.T) {
	assert.True(t, resourceMatches("https://example.com/mcp#section", "https://example.com"))
}

func TestResourceMatches_MultipleSlashes(t *testing.T) {
	assert.True(t, resourceMatches("https://example.com///", "https://example.com"))
}

func TestResourceMatches_InvalidResource(t *testing.T) {
	assert.False(t, resourceMatches("://invalid", "https://example.com"))
}

func TestResourceMatches_InvalidServer(t *testing.T) {
	assert.False(t, resourceMatches("https://example.com/mcp", "://invalid"))
}

// --- validateRedirectURI tests ---

func TestValidateRedirectURI_ExactMatch(t *testing.T) {
	client := &OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{"https://example.com/callback"},
	}
	ok := validateRedirectURI(client, "https://example.com/callback")
	assert.True(t, ok)
}

func TestValidateRedirectURI_MultipleRegistered(t *testing.T) {
	client := &OAuthClient{
		ClientID: "client1",
		RedirectURIs: []string{
			"https://example.com/callback",
			"https://other.com/auth",
			"http://127.0.0.1/local",
		},
	}

	assert.True(t, validateRedirectURI(client, "https://example.com/callback"))
	assert.True(t, validateRedirectURI(client, "https://other.com/auth"))
	assert.True(t, validateRedirectURI(client, "http://127.0.0.1/local"))
	assert.False(t, validateRedirectURI(client, "https://evil.com/callback"))
}

func TestValidateRedirectURI_LoopbackDynamicPort(t *testing.T) {
	client := &OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{"http://127.0.0.1/callback"},
	}

	assert.True(t, validateRedirectURI(client, "http://127.0.0.1:8080/callback"))
	assert.True(t, validateRedirectURI(client, "http://127.0.0.1:9999/callback"))
	assert.True(t, validateRedirectURI(client, "http://127.0.0.1/callback"))
	assert.False(t, validateRedirectURI(client, "http://127.0.0.1:8080/different"))
}

func TestValidateRedirectURI_LoopbackIPv6(t *testing.T) {
	client := &OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{"http://[::1]/callback"},
	}

	assert.True(t, validateRedirectURI(client, "http://[::1]:8080/callback"))
	assert.True(t, validateRedirectURI(client, "http://[::1]/callback"))
}

func TestValidateRedirectURI_NoRegisteredDefaultsToLoopback(t *testing.T) {
	client := &OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{},
	}

	assert.True(t, validateRedirectURI(client, "http://127.0.0.1:8080/callback"))
	assert.True(t, validateRedirectURI(client, "http://[::1]:9999/auth"))
	assert.False(t, validateRedirectURI(client, "https://example.com/callback"))
	assert.False(t, validateRedirectURI(client, "http://localhost:8080/callback"))
}

func TestValidateRedirectURI_HttpsNotLoopback(t *testing.T) {
	client := &OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{"https://example.com/callback"},
	}

	// HTTPS URIs don't get dynamic port matching
	assert.False(t, validateRedirectURI(client, "https://example.com:8443/callback"))
}

func TestValidateRedirectURI_InvalidURI(t *testing.T) {
	client := &OAuthClient{
		ClientID:     "client1",
		RedirectURIs: []string{},
	}

	assert.False(t, validateRedirectURI(client, "not a valid URI"))
}

// --- isLoopbackHost tests ---

func TestIsLoopbackHost_IPv4Loopback(t *testing.T) {
	assert.True(t, isLoopbackHost("127.0.0.1"))
}

func TestIsLoopbackHost_IPv6Loopback(t *testing.T) {
	assert.True(t, isLoopbackHost("::1"))
}

func TestIsLoopbackHost_Localhost(t *testing.T) {
	assert.False(t, isLoopbackHost("localhost"))
}

func TestIsLoopbackHost_LocalhostWithDomain(t *testing.T) {
	assert.False(t, isLoopbackHost("localhost.localdomain"))
}

func TestIsLoopbackHost_IPv4NonLoopback(t *testing.T) {
	assert.False(t, isLoopbackHost("192.168.1.1"))
	assert.False(t, isLoopbackHost("10.0.0.1"))
}

func TestIsLoopbackHost_IPv6NonLoopback(t *testing.T) {
	assert.False(t, isLoopbackHost("2001:db8::1"))
}

func TestIsLoopbackHost_Empty(t *testing.T) {
	assert.False(t, isLoopbackHost(""))
}

// --- isLoopbackRegistered tests ---

func TestIsLoopbackRegistered_ValidLoopback(t *testing.T) {
	assert.True(t, isLoopbackRegistered("http://127.0.0.1/callback"))
	assert.True(t, isLoopbackRegistered("http://[::1]/callback"))
}

func TestIsLoopbackRegistered_NotLoopback(t *testing.T) {
	assert.False(t, isLoopbackRegistered("https://example.com/callback"))
	assert.False(t, isLoopbackRegistered("http://localhost/callback"))
}

func TestIsLoopbackRegistered_HttpsLoopback(t *testing.T) {
	assert.False(t, isLoopbackRegistered("https://127.0.0.1/callback"))
}

func TestIsLoopbackRegistered_InvalidURI(t *testing.T) {
	assert.False(t, isLoopbackRegistered("not a valid URI"))
}

// --- validateRedirectScheme tests ---

func TestValidateRedirectScheme_Https(t *testing.T) {
	err := validateRedirectScheme("https://example.com/callback")
	assert.NoError(t, err)
}

func TestValidateRedirectScheme_HttpLoopbackIPv4(t *testing.T) {
	err := validateRedirectScheme("http://127.0.0.1/callback")
	assert.NoError(t, err)
}

func TestValidateRedirectScheme_HttpLoopbackIPv6(t *testing.T) {
	err := validateRedirectScheme("http://[::1]/callback")
	assert.NoError(t, err)
}

func TestValidateRedirectScheme_HttpNonLoopback(t *testing.T) {
	err := validateRedirectScheme("http://example.com/callback")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestValidateRedirectScheme_HttpLocalhost(t *testing.T) {
	err := validateRedirectScheme("http://localhost/callback")
	assert.Error(t, err)
}

func TestValidateRedirectScheme_CustomScheme(t *testing.T) {
	err := validateRedirectScheme("myapp://callback")
	assert.Error(t, err)
}

func TestValidateRedirectScheme_InvalidURI(t *testing.T) {
	err := validateRedirectScheme("://invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid URI")
}

func TestValidateRedirectScheme_HttpLoopbackWithPort(t *testing.T) {
	err := validateRedirectScheme("http://127.0.0.1:8080/callback")
	assert.NoError(t, err)
}

// --- redirectWithError tests ---

func TestRedirectWithError_BasicError(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	redirectWithError(w, r, "https://example.com/callback", "", "access_denied", "User denied access")

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://example.com/callback?")
	assert.Contains(t, location, "error=access_denied")
	assert.Contains(t, location, "error_description=User+denied+access")
}

func TestRedirectWithError_WithState(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	redirectWithError(w, r, "https://example.com/callback", "abc123", "invalid_request", "Bad request")

	location := w.Header().Get("Location")
	assert.Contains(t, location, "state=abc123")
	assert.Contains(t, location, "error=invalid_request")
}

func TestRedirectWithError_ExistingQueryParams(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	redirectWithError(w, r, "https://example.com/callback?foo=bar", "", "server_error", "Internal error")

	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://example.com/callback?foo=bar&")
	assert.Contains(t, location, "error=server_error")
}

func TestRedirectWithError_SpecialCharsInDescription(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	redirectWithError(w, r, "https://example.com/callback", "", "invalid_request", "Error: user@example.com invalid")

	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
	// URL encoding should handle special characters
	assert.Contains(t, location, "error_description=")
}

// --- writeJSONError tests ---

func TestWriteJSONError_BasicError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "invalid_request", "Missing parameter")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", resp["error"])
	assert.Equal(t, "Missing parameter", resp["error_description"])
}

func TestWriteJSONError_UnauthorizedError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestWriteJSONError_EmptyDescription(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "invalid_request", "")

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", resp["error"])
	assert.Equal(t, "", resp["error_description"])
}