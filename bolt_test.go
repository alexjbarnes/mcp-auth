package mcpauth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bolt "go.etcd.io/bbolt"
)

func openTestBolt(t *testing.T) *bolt.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.Remove(path)
	})

	return db
}

func testBoltPersist(t *testing.T) Persistence {
	t.Helper()
	p, err := NewBoltPersistence(openTestBolt(t))
	require.NoError(t, err)

	return p
}

// --- CreateBoltBuckets ---

func TestCreateBoltBuckets_Idempotent(t *testing.T) {
	db := openTestBolt(t)
	// First call creates buckets (via NewBoltPersistence or directly).
	require.NoError(t, CreateBoltBuckets(db))
	// Second call should not error.
	require.NoError(t, CreateBoltBuckets(db))
}

// --- Token CRUD ---

func TestBolt_SaveAndLoadToken(t *testing.T) {
	p := testBoltPersist(t)

	tok := OAuthToken{
		TokenHash:   HashSecret("tok1"),
		Kind:        "access",
		UserID:      "user1",
		ClientID:    "client1",
		Resource:    "https://example.com",
		Scopes:      []string{"read", "write"},
		ExpiresAt:   time.Now().Add(time.Hour).Truncate(time.Second).UTC(),
		RefreshHash: HashSecret("refresh1"),
	}

	require.NoError(t, p.SaveOAuthToken(tok))

	tokens, err := p.AllOAuthTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)

	got := tokens[0]
	assert.Equal(t, tok.TokenHash, got.TokenHash)
	assert.Equal(t, tok.Kind, got.Kind)
	assert.Equal(t, tok.UserID, got.UserID)
	assert.Equal(t, tok.ClientID, got.ClientID)
	assert.Equal(t, tok.Resource, got.Resource)
	assert.Equal(t, tok.Scopes, got.Scopes)
	assert.True(t, tok.ExpiresAt.Equal(got.ExpiresAt))
	assert.Equal(t, tok.RefreshHash, got.RefreshHash)
}

func TestBolt_SaveToken_Upsert(t *testing.T) {
	p := testBoltPersist(t)

	hash := HashSecret("tok-upsert")
	tok := OAuthToken{
		TokenHash: hash,
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second).UTC(),
	}
	require.NoError(t, p.SaveOAuthToken(tok))

	tok.UserID = "user2"
	require.NoError(t, p.SaveOAuthToken(tok))

	tokens, err := p.AllOAuthTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "user2", tokens[0].UserID)
}

func TestBolt_DeleteToken(t *testing.T) {
	p := testBoltPersist(t)

	hash := HashSecret("tok-delete")
	require.NoError(t, p.SaveOAuthToken(OAuthToken{
		TokenHash: hash,
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second).UTC(),
	}))

	require.NoError(t, p.DeleteOAuthToken(hash))

	tokens, err := p.AllOAuthTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

func TestBolt_DeleteToken_Nonexistent(t *testing.T) {
	p := testBoltPersist(t)
	require.NoError(t, p.DeleteOAuthToken("nonexistent"))
}

func TestBolt_AllTokens_Empty(t *testing.T) {
	p := testBoltPersist(t)
	tokens, err := p.AllOAuthTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

func TestBolt_Token_NilScopes(t *testing.T) {
	p := testBoltPersist(t)

	tok := OAuthToken{
		TokenHash: HashSecret("nil-scopes"),
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second).UTC(),
	}
	require.NoError(t, p.SaveOAuthToken(tok))

	tokens, err := p.AllOAuthTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Nil(t, tokens[0].Scopes)
}

// --- Client CRUD ---

func TestBolt_SaveAndLoadClient(t *testing.T) {
	p := testBoltPersist(t)

	c := OAuthClient{
		ClientID:                "client1",
		ClientName:              "Test Client",
		RedirectURIs:            []string{"https://example.com/callback", "https://example.com/cb2"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		SecretHash:              HashSecret("secret"),
		IssuedAt:                time.Now().Unix(),
		UserID:                  "app-user-1",
	}

	require.NoError(t, p.SaveOAuthClient(c))

	clients, err := p.AllOAuthClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)

	got := clients[0]
	assert.Equal(t, c.ClientID, got.ClientID)
	assert.Equal(t, c.ClientName, got.ClientName)
	assert.Equal(t, c.RedirectURIs, got.RedirectURIs)
	assert.Equal(t, c.GrantTypes, got.GrantTypes)
	assert.Equal(t, c.ResponseTypes, got.ResponseTypes)
	assert.Equal(t, c.TokenEndpointAuthMethod, got.TokenEndpointAuthMethod)
	assert.Equal(t, c.SecretHash, got.SecretHash)
	assert.Equal(t, c.IssuedAt, got.IssuedAt)
	assert.Equal(t, c.UserID, got.UserID)
}

func TestBolt_SaveClient_Upsert(t *testing.T) {
	p := testBoltPersist(t)

	c := OAuthClient{
		ClientID:     "client-upsert",
		ClientName:   "Original",
		RedirectURIs: []string{"https://example.com/cb"},
	}
	require.NoError(t, p.SaveOAuthClient(c))

	c.ClientName = "Updated"
	require.NoError(t, p.SaveOAuthClient(c))

	clients, err := p.AllOAuthClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "Updated", clients[0].ClientName)
}

func TestBolt_DeleteClient(t *testing.T) {
	p := testBoltPersist(t)

	require.NoError(t, p.SaveOAuthClient(OAuthClient{
		ClientID:     "to-delete",
		RedirectURIs: []string{"https://example.com/cb"},
	}))

	require.NoError(t, p.DeleteOAuthClient("to-delete"))

	clients, err := p.AllOAuthClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

func TestBolt_DeleteClient_Nonexistent(t *testing.T) {
	p := testBoltPersist(t)
	require.NoError(t, p.DeleteOAuthClient("nonexistent"))
}

func TestBolt_AllClients_Empty(t *testing.T) {
	p := testBoltPersist(t)
	clients, err := p.AllOAuthClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

func TestBolt_Client_EmptySliceFields(t *testing.T) {
	p := testBoltPersist(t)

	c := OAuthClient{
		ClientID: "bare-client",
	}
	require.NoError(t, p.SaveOAuthClient(c))

	clients, err := p.AllOAuthClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Nil(t, clients[0].RedirectURIs)
	assert.Nil(t, clients[0].GrantTypes)
	assert.Nil(t, clients[0].ResponseTypes)
}

// --- API Key CRUD ---

func TestBolt_SaveAndLoadAPIKey(t *testing.T) {
	p := testBoltPersist(t)

	hash := HashSecret("apikey1")
	ak := APIKey{
		KeyHash:   hash,
		UserID:    "user1",
		CreatedAt: time.Now().Truncate(time.Second).UTC(),
	}

	require.NoError(t, p.SaveAPIKey(hash, ak))

	keys, err := p.AllAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	got, ok := keys[hash]
	require.True(t, ok)
	assert.Equal(t, ak.UserID, got.UserID)
	assert.True(t, ak.CreatedAt.Equal(got.CreatedAt))
	assert.Equal(t, hash, got.KeyHash)
}

func TestBolt_SaveAPIKey_Upsert(t *testing.T) {
	p := testBoltPersist(t)

	hash := HashSecret("apikey-upsert")
	ak := APIKey{
		KeyHash:   hash,
		UserID:    "user1",
		CreatedAt: time.Now().Truncate(time.Second).UTC(),
	}
	require.NoError(t, p.SaveAPIKey(hash, ak))

	ak.UserID = "user2"
	require.NoError(t, p.SaveAPIKey(hash, ak))

	keys, err := p.AllAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "user2", keys[hash].UserID)
}

func TestBolt_DeleteAPIKey(t *testing.T) {
	p := testBoltPersist(t)

	hash := HashSecret("apikey-delete")
	require.NoError(t, p.SaveAPIKey(hash, APIKey{
		KeyHash:   hash,
		UserID:    "user1",
		CreatedAt: time.Now().Truncate(time.Second).UTC(),
	}))

	require.NoError(t, p.DeleteAPIKey(hash))

	keys, err := p.AllAPIKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestBolt_DeleteAPIKey_Nonexistent(t *testing.T) {
	p := testBoltPersist(t)
	require.NoError(t, p.DeleteAPIKey("nonexistent"))
}

func TestBolt_AllAPIKeys_Empty(t *testing.T) {
	p := testBoltPersist(t)
	keys, err := p.AllAPIKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// --- Multiple records ---

func TestBolt_MultipleTokens(t *testing.T) {
	p := testBoltPersist(t)

	for i, name := range []string{"a", "b", "c"} {
		require.NoError(t, p.SaveOAuthToken(OAuthToken{
			TokenHash: HashSecret(name),
			Kind:      "access",
			UserID:    "user" + name,
			ExpiresAt: time.Now().Add(time.Duration(i+1) * time.Hour).Truncate(time.Second).UTC(),
		}))
	}

	tokens, err := p.AllOAuthTokens()
	require.NoError(t, err)
	assert.Len(t, tokens, 3)
}

func TestBolt_MultipleClients(t *testing.T) {
	p := testBoltPersist(t)

	for _, id := range []string{"c1", "c2", "c3"} {
		require.NoError(t, p.SaveOAuthClient(OAuthClient{
			ClientID:     id,
			RedirectURIs: []string{"https://example.com/cb"},
		}))
	}

	clients, err := p.AllOAuthClients()
	require.NoError(t, err)
	assert.Len(t, clients, 3)
}

func TestBolt_MultipleAPIKeys(t *testing.T) {
	p := testBoltPersist(t)

	for _, raw := range []string{"key1", "key2", "key3"} {
		hash := HashSecret(raw)
		require.NoError(t, p.SaveAPIKey(hash, APIKey{
			KeyHash:   hash,
			UserID:    "user-" + raw,
			CreatedAt: time.Now().Truncate(time.Second).UTC(),
		}))
	}

	keys, err := p.AllAPIKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

// --- Integration: bbolt persistence with store ---

func TestBolt_StoreIntegration(t *testing.T) {
	p := testBoltPersist(t)
	s := newStore(p, testLogger(), nil)
	t.Cleanup(s.stop)

	// Register a client.
	ok := s.RegisterClient(&OAuthClient{
		ClientID:     "int-client",
		RedirectURIs: []string{"https://example.com/cb"},
	})
	require.True(t, ok)

	// Save a token.
	s.SaveToken(&OAuthToken{
		Token:     "int-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Register an API key.
	rawKey := RandomHex(32)
	s.RegisterAPIKey(rawKey, "user1")

	// Verify via persistence.
	clients, err := p.AllOAuthClients()
	require.NoError(t, err)
	assert.Len(t, clients, 1)

	tokens, err := p.AllOAuthTokens()
	require.NoError(t, err)
	assert.Len(t, tokens, 1)

	keys, err := p.AllAPIKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	// Create a second store from the same persistence to verify round-trip.
	s2 := newStore(p, testLogger(), nil)
	t.Cleanup(s2.stop)

	assert.NotNil(t, s2.GetClient("int-client"))
	assert.NotNil(t, s2.ValidateToken("int-token"))
	assert.NotNil(t, s2.ValidateAPIKey(rawKey))
}

func TestBolt_StoreRemoveClient(t *testing.T) {
	p := testBoltPersist(t)
	s := newStore(p, testLogger(), nil)
	t.Cleanup(s.stop)

	s.RegisterPreConfiguredClient(&OAuthClient{
		ClientID:   "remove-me",
		GrantTypes: []string{"client_credentials"},
		SecretHash: HashSecret("secret"),
	})

	assert.True(t, s.RemoveClient("remove-me"))

	clients, err := p.AllOAuthClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

func TestBolt_StoreCleanupDeletesExpired(t *testing.T) {
	p := testBoltPersist(t)
	s := newStore(p, testLogger(), nil)
	t.Cleanup(s.stop)

	s.SaveToken(&OAuthToken{
		Token:     "expired-bolt",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-time.Minute),
	})

	s.cleanup()

	tokens, err := p.AllOAuthTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}
