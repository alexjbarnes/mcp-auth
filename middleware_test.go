package mcpauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMiddleware_ValidToken(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	token := &OAuthToken{
		Token:     "valid-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.SaveToken(token)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestMiddleware_MissingToken(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "resource_metadata")
	assert.NotContains(t, wwwAuth, "invalid_token")
}

func TestMiddleware_InvalidToken(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer unknown-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "error=\"invalid_token\"")
}

func TestMiddleware_ExpiredToken(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	token := &OAuthToken{
		Token:     "expired-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	s.SaveToken(token)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer expired-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "error=\"invalid_token\"")
}

func TestMiddleware_NonBearerAuth(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Basic foo:bar")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_InjectsRequestContext(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	token := &OAuthToken{
		Token:     "ctx-token",
		Kind:      "access",
		UserID:    "ctx-user",
		ClientID:  "ctx-client",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.SaveToken(token)

	var capturedUserID, capturedClientID, capturedIP string

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserID = RequestUserID(r.Context())
		capturedClientID = RequestClientID(r.Context())
		capturedIP = RequestRemoteIP(r.Context())

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer ctx-token")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "ctx-user", capturedUserID)
	assert.Equal(t, "ctx-client", capturedClientID)
	assert.Equal(t, "192.168.1.1", capturedIP)
}

func TestMiddleware_ExpiredTokenHeader(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	token := &OAuthToken{
		Token:     "expired-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	s.SaveToken(token)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer expired-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "error=\"invalid_token\"")
	assert.Contains(t, wwwAuth, "resource_metadata")
}

func TestMiddleware_RefreshTokenAsBearer(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	token := &OAuthToken{
		Token:     "refresh-token",
		Kind:      "refresh",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.SaveToken(token)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer refresh-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "error=\"invalid_token\"")
}

func TestMiddleware_WrongResourceOnToken(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)

	token := &OAuthToken{
		Token:     "token-wrong-resource",
		Kind:      "access",
		UserID:    "user1",
		Resource:  "https://other-server.com",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.SaveToken(token)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer token-wrong-resource")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "error=\"invalid_token\"")
}

func TestMiddleware_APIKey_Valid(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "vs_", "", nil)

	s.RegisterAPIKey("vs_testkey123", "apiuser")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer vs_testkey123")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestMiddleware_APIKey_Invalid(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "vs_", "", nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer vs_wrongkey")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "error=\"invalid_token\"")
}

func TestMiddleware_APIKey_RevokedReturns401(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "vs_", "", nil)

	s.RegisterAPIKey("vs_testkey123", "apiuser")
	s.RevokeAPIKey(HashSecret("vs_testkey123"))

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer vs_testkey123")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_APIKey_DoesNotAffectOAuthTokens(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "vs_", "", nil)

	// Register both API key and OAuth token
	s.RegisterAPIKey("vs_testkey123", "apiuser")

	token := &OAuthToken{
		Token:     "oauth-token",
		Kind:      "access",
		UserID:    "oauthuser",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.SaveToken(token)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	// Test OAuth token still works
	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer oauth-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestMiddleware_APIKey_ClientIDMatchesUserID(t *testing.T) {
	s := testStore(t)
	mw := authMiddleware(s, testLogger(), testServerURL, "vs_", "", nil)

	s.RegisterAPIKey("vs_testkey123", "apiuser")

	var capturedClientID string

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClientID = RequestClientID(r.Context())

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer vs_testkey123")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "apiuser", capturedClientID)
}

// --- Trusted proxy header tests ---

func TestMiddleware_TrustedProxyHeader(t *testing.T) {
	s := testStore(t)
	s.SaveToken(&OAuthToken{
		Token:     "proxy-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	mw := authMiddleware(s, testLogger(), testServerURL, "", "X-Forwarded-For", nil)

	var capturedIP string

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIP = RequestRemoteIP(r.Context())

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer proxy-token")
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "203.0.113.50", capturedIP)
}

func TestMiddleware_NoProxyHeaderFallsBack(t *testing.T) {
	s := testStore(t)
	s.SaveToken(&OAuthToken{
		Token:     "fallback-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	mw := authMiddleware(s, testLogger(), testServerURL, "", "X-Forwarded-For", nil)

	var capturedIP string

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIP = RequestRemoteIP(r.Context())

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer fallback-token")
	// No X-Forwarded-For header, falls back to RemoteAddr.
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, capturedIP)
}

// --- User account active check tests ---

// testAccountChecker implements both UserAuthenticator and UserAccountChecker.
type testAccountChecker struct {
	MapAuthenticator
	disabled map[string]bool
}

func (c *testAccountChecker) IsAccountActive(_ context.Context, userID string) (bool, error) {
	return !c.disabled[userID], nil
}

func TestMiddleware_AccountChecker_ActiveUser(t *testing.T) {
	s := testStore(t)
	s.SaveToken(&OAuthToken{
		Token:     "active-user-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	checker := &testAccountChecker{
		MapAuthenticator: NewMapAuthenticator(map[string]string{"user1": "pass"}),
		disabled:         map[string]bool{},
	}

	mw := authMiddleware(s, testLogger(), testServerURL, "", "", checker)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer active-user-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_AccountChecker_DisabledUser(t *testing.T) {
	s := testStore(t)
	s.SaveToken(&OAuthToken{
		Token:     "disabled-user-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	checker := &testAccountChecker{
		MapAuthenticator: NewMapAuthenticator(map[string]string{"user1": "pass"}),
		disabled:         map[string]bool{"user1": true},
	}

	mw := authMiddleware(s, testLogger(), testServerURL, "", "", checker)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for disabled user")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer disabled-user-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "invalid_token")
}

func TestMiddleware_AccountChecker_DisabledAPIKeyUser(t *testing.T) {
	s := testStore(t)
	s.RegisterAPIKey("vs_disabled_key", "disabled-user")

	checker := &testAccountChecker{
		MapAuthenticator: NewMapAuthenticator(map[string]string{}),
		disabled:         map[string]bool{"disabled-user": true},
	}

	mw := authMiddleware(s, testLogger(), testServerURL, "vs_", "", checker)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for disabled user")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer vs_disabled_key")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestMiddleware_NoAccountChecker_SkipsCheck(t *testing.T) {
	s := testStore(t)
	s.SaveToken(&OAuthToken{
		Token:     "no-checker-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	// Pass nil for users -- no account checking.
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer no-checker-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_PlainUserAuth_SkipsAccountCheck(t *testing.T) {
	s := testStore(t)
	s.SaveToken(&OAuthToken{
		Token:     "plain-auth-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	// Pass a plain UserAuthenticator (not UserAccountChecker).
	// Account check should be skipped.
	users := NewMapAuthenticator(map[string]string{"user1": "pass"})
	mw := authMiddleware(s, testLogger(), testServerURL, "", "", users)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer plain-auth-token")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- WithUserID tests ---

func TestWithUserID_RoundTrip(t *testing.T) {
	ctx := WithUserID(context.Background(), "test-user")
	assert.Equal(t, "test-user", RequestUserID(ctx))
}

func TestWithUserID_Empty(t *testing.T) {
	ctx := WithUserID(context.Background(), "")
	assert.Empty(t, RequestUserID(ctx))
}

