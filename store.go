package mcpauth

import (
	"crypto/subtle"
	"log/slog"
	"sync"
	"time"
)

const (
	// maxClients caps the number of registered clients to prevent
	// unbounded growth from unauthenticated registration requests.
	maxClients = 100

	// csrfExpiry controls how long a CSRF token remains valid.
	csrfExpiry = 10 * time.Minute

	// cleanupInterval controls how often expired entries are reaped.
	cleanupInterval = 5 * time.Minute

	// maxRegistrationsPerMinute caps dynamic client registrations.
	maxRegistrationsPerMinute = 10

	// dummyHash is used for timing-safe comparisons when no stored hash exists.
	dummyHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// csrfEntry tracks a CSRF token with its expiry and bound OAuth parameters.
type csrfEntry struct {
	expiresAt   time.Time
	clientID    string
	redirectURI string
}

// store holds all OAuth state. Tokens and clients are backed by a
// Persistence implementation when provided; auth codes and CSRF tokens
// are always in-memory only.
type store struct {
	mu           sync.RWMutex
	codes        map[string]*Code
	tokens       map[string]*OAuthToken
	refreshIndex map[string]string
	clients      map[string]*OAuthClient
	apiKeys      map[string]*APIKey
	csrf         map[string]csrfEntry
	stopGC       chan struct{}

	registrationTimes []time.Time

	persist         Persistence
	logger          *slog.Logger
	secretValidator func(string, string) bool
}

// newStore creates an OAuth store. If persist is non-nil, existing tokens
// and client registrations are loaded. Pass nil for in-memory-only operation.
// The secretValidator, when non-nil, replaces the default SHA-256
// comparison in ValidateClientSecret.
func newStore(persist Persistence, logger *slog.Logger, secretValidator func(string, string) bool) *store {
	s := &store{
		codes:           make(map[string]*Code),
		tokens:          make(map[string]*OAuthToken),
		refreshIndex:    make(map[string]string),
		clients:         make(map[string]*OAuthClient),
		apiKeys:         make(map[string]*APIKey),
		csrf:            make(map[string]csrfEntry),
		stopGC:          make(chan struct{}),
		persist:         persist,
		logger:          logger,
		secretValidator: secretValidator,
	}

	if persist != nil {
		s.loadFromDisk()
	}

	go s.gcLoop()

	return s
}

// loadFromDisk populates the in-memory maps from persistence.
func (s *store) loadFromDisk() {
	now := time.Now()

	tokens, err := s.persist.AllOAuthTokens()
	if err != nil {
		s.logger.Warn("loading persisted OAuth tokens", slog.String("error", err.Error()))
	}

	for i := range tokens {
		t := tokens[i]

		needsMigration := t.TokenHash == "" && t.Token != ""
		if needsMigration {
			t.TokenHash = HashSecret(t.Token)
		}

		if t.TokenHash == "" {
			continue
		}

		if now.After(t.ExpiresAt) {
			_ = s.persist.DeleteOAuthToken(t.TokenHash)
			continue
		}

		if t.Kind == "access" && t.RefreshHash == "" && t.RefreshToken != "" {
			t.RefreshHash = HashSecret(t.RefreshToken)
			needsMigration = true
		}

		if needsMigration {
			if err := s.persist.SaveOAuthToken(t); err != nil {
				s.logger.Warn("migrating legacy token",
					slog.String("error", err.Error()),
				)
			}
		}

		t.Token = ""
		t.RefreshToken = ""

		s.tokens[t.TokenHash] = &t

		if t.Kind == "access" && t.RefreshHash != "" {
			s.refreshIndex[t.RefreshHash] = t.TokenHash
		}
	}

	clients, err := s.persist.AllOAuthClients()
	if err != nil {
		s.logger.Warn("loading persisted OAuth clients", slog.String("error", err.Error()))
	}

	for i := range clients {
		c := clients[i]
		s.clients[c.ClientID] = &c
	}

	apiKeys, err := s.persist.AllAPIKeys()
	if err != nil {
		s.logger.Warn("loading persisted API keys", slog.String("error", err.Error()))
	}

	for hash, ak := range apiKeys {
		akCopy := ak
		s.apiKeys[hash] = &akCopy
	}

	s.logger.Info("loaded auth state from disk",
		slog.Int("tokens", len(s.tokens)),
		slog.Int("clients", len(s.clients)),
		slog.Int("api_keys", len(s.apiKeys)),
	)
}

// stop terminates the background cleanup goroutine.
func (s *store) stop() {
	close(s.stopGC)
}

// gcLoop periodically removes expired tokens, codes, and CSRF tokens.
func (s *store) gcLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopGC:
			return
		}
	}
}

// cleanup removes all expired entries from the store.
func (s *store) cleanup() {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, ac := range s.codes {
		if now.After(ac.ExpiresAt) {
			delete(s.codes, k)
		}
	}

	for hash, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, hash)

			if t.Kind == "access" && t.RefreshHash != "" {
				delete(s.refreshIndex, t.RefreshHash)
			}

			if s.persist != nil {
				_ = s.persist.DeleteOAuthToken(hash)
			}
		}
	}

	for k, entry := range s.csrf {
		if now.After(entry.expiresAt) {
			delete(s.csrf, k)
		}
	}
}

// SaveCode stores an authorization code.
func (s *store) SaveCode(ac *Code) {
	ac.active = true

	s.mu.Lock()
	s.codes[ac.Code] = ac
	s.mu.Unlock()
}

// ConsumeCode retrieves an authorization code. On first use, the code
// is marked inactive and returned with replayed=false. A second attempt
// returns the code with replayed=true so the caller can revoke tokens
// issued from the original exchange (RFC 6819 Section 4.4.1.1).
// Returns (nil, false) if the code does not exist or has expired.
func (s *store) ConsumeCode(code string) (ac *Code, replayed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ac, ok := s.codes[code]
	if !ok {
		return nil, false
	}

	if time.Now().After(ac.ExpiresAt) {
		delete(s.codes, code)
		return nil, false
	}

	if !ac.active {
		return ac, true
	}

	ac.active = false

	return ac, false
}

// RevokeClientTokens removes all tokens (access and refresh) issued
// for the given client ID. Used for replay detection to revoke tokens
// that may have been issued from a compromised authorization code.
func (s *store) RevokeClientTokens(clientID string) {
	s.mu.Lock()

	var toDelete []string

	for hash, t := range s.tokens {
		if t.ClientID == clientID {
			toDelete = append(toDelete, hash)

			if t.Kind == "access" && t.RefreshHash != "" {
				delete(s.refreshIndex, t.RefreshHash)
			}
		}
	}

	for _, hash := range toDelete {
		delete(s.tokens, hash)
	}

	s.mu.Unlock()

	if s.persist != nil {
		for _, hash := range toDelete {
			_ = s.persist.DeleteOAuthToken(hash)
		}
	}
}

// SaveToken stores a token in memory and persists it to disk.
func (s *store) SaveToken(t *OAuthToken) {
	if t.TokenHash == "" {
		t.TokenHash = HashSecret(t.Token)
	}

	if t.RefreshHash == "" && t.RefreshToken != "" {
		t.RefreshHash = HashSecret(t.RefreshToken)
	}

	s.mu.Lock()
	s.tokens[t.TokenHash] = t

	if t.Kind == "access" && t.RefreshHash != "" {
		s.refreshIndex[t.RefreshHash] = t.TokenHash
	}

	s.mu.Unlock()

	if s.persist != nil {
		if err := s.persist.SaveOAuthToken(*t); err != nil && s.logger != nil {
			s.logger.Warn("persisting OAuth token", slog.String("error", err.Error()))
		}
	}
}

// ValidateToken checks if an access token is valid and not expired.
// Returns nil if invalid. Refresh tokens are rejected.
func (s *store) ValidateToken(token string) *OAuthToken {
	hash := HashSecret(token)

	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[hash]
	if !ok {
		return nil
	}

	if time.Now().After(t.ExpiresAt) {
		return nil
	}

	if t.Kind == "refresh" {
		return nil
	}

	return t
}

// validateRefreshTokenLocked performs refresh token validation without locking.
// Caller must hold at least s.mu.RLock().
func (s *store) validateRefreshTokenLocked(tokenHash, clientID, resource string) *OAuthToken {
	t, ok := s.tokens[tokenHash]
	if !ok {
		return nil
	}

	if time.Now().After(t.ExpiresAt) {
		return nil
	}

	if t.Kind != "refresh" {
		return nil
	}

	if t.ClientID != "" {
		if clientID == "" || t.ClientID != clientID {
			return nil
		}
	}

	if resource != "" && !resourceMatches(resource, t.Resource) {
		return nil
	}

	return t
}

// ConsumeRefreshToken atomically validates and deletes a refresh token.
// Returns nil if the token is invalid.
func (s *store) ConsumeRefreshToken(token, clientID, resource string) *OAuthToken {
	hash := HashSecret(token)

	s.mu.Lock()
	defer s.mu.Unlock()

	t := s.validateRefreshTokenLocked(hash, clientID, resource)
	if t == nil {
		return nil
	}

	delete(s.tokens, hash)

	if s.persist != nil {
		_ = s.persist.DeleteOAuthToken(hash)
	}

	return t
}

// DeleteAccessTokenByRefreshToken removes the access token that was
// paired with the given refresh token.
func (s *store) DeleteAccessTokenByRefreshToken(refreshToken string) {
	refreshHash := HashSecret(refreshToken)

	s.mu.Lock()

	found := s.refreshIndex[refreshHash]
	if found != "" {
		delete(s.tokens, found)
		delete(s.refreshIndex, refreshHash)
	}

	s.mu.Unlock()

	if found != "" && s.persist != nil {
		_ = s.persist.DeleteOAuthToken(found)
	}
}

// RegistrationAllowed checks whether a new registration is allowed under
// the rate limit.
func (s *store) RegistrationAllowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	window := now.Add(-1 * time.Minute)

	valid := s.registrationTimes[:0]
	for _, t := range s.registrationTimes {
		if t.After(window) {
			valid = append(valid, t)
		}
	}

	s.registrationTimes = valid

	if len(s.registrationTimes) >= maxRegistrationsPerMinute {
		return false
	}

	s.registrationTimes = append(s.registrationTimes, now)

	return true
}

// RegisterClient stores a new client registration. Returns false if the
// maximum number of registered clients has been reached.
func (s *store) RegisterClient(ci *OAuthClient) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.clients) >= maxClients {
		return false
	}

	s.clients[ci.ClientID] = ci

	if s.persist != nil {
		if err := s.persist.SaveOAuthClient(*ci); err != nil && s.logger != nil {
			s.logger.Warn("persisting OAuth client", slog.String("error", err.Error()))
		}
	}

	return true
}

// GetClient returns the client info for a given client_id, or nil.
func (s *store) GetClient(clientID string) *OAuthClient {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.clients[clientID]
}

// SaveCSRF stores a CSRF token bound to specific OAuth parameters.
func (s *store) SaveCSRF(token, clientID, redirectURI string) {
	s.mu.Lock()
	s.csrf[token] = csrfEntry{
		expiresAt:   time.Now().Add(csrfExpiry),
		clientID:    clientID,
		redirectURI: redirectURI,
	}
	s.mu.Unlock()
}

// ConsumeCSRF retrieves and deletes a CSRF token. Returns false if
// the token is invalid, expired, or was issued for different OAuth
// parameters.
func (s *store) ConsumeCSRF(token, clientID, redirectURI string) bool {
	if token == "" {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.csrf[token]
	if !ok {
		return false
	}

	delete(s.csrf, token)

	if time.Now().After(entry.expiresAt) {
		return false
	}

	return entry.clientID == clientID && entry.redirectURI == redirectURI
}

// ValidateClientSecret checks the provided secret against the stored
// hash for the given client. When a custom secretValidator is set, it
// delegates to that function. Otherwise it computes SHA-256(secret) and
// performs a constant-time comparison against the stored hash.
func (s *store) ValidateClientSecret(clientID, secret string) bool {
	s.mu.RLock()

	storedHash := ""
	if client, ok := s.clients[clientID]; ok {
		storedHash = client.SecretHash
	}

	s.mu.RUnlock()

	if s.secretValidator != nil {
		if storedHash == "" {
			return false
		}

		return s.secretValidator(secret, storedHash)
	}

	if storedHash == "" {
		storedHash = dummyHash
	}

	computed := HashSecret(secret)

	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}

// RemoveClient removes a single client by ID. Returns true if the
// client existed and was removed.
func (s *store) RemoveClient(clientID string) bool {
	s.mu.Lock()

	_, existed := s.clients[clientID]
	if existed {
		delete(s.clients, clientID)
	}

	s.mu.Unlock()

	if existed && s.persist != nil {
		_ = s.persist.DeleteOAuthClient(clientID)
	}

	return existed
}

// RegisterPreConfiguredClient stores a pre-configured client. Unlike
// RegisterClient, this bypasses the maxClients cap.
func (s *store) RegisterPreConfiguredClient(client *OAuthClient) {
	s.mu.Lock()
	s.clients[client.ClientID] = client
	s.mu.Unlock()

	if s.persist != nil {
		if err := s.persist.SaveOAuthClient(*client); err != nil && s.logger != nil {
			s.logger.Warn("persisting pre-configured client", slog.String("error", err.Error()))
		}
	}
}

// RegisterAPIKey stores an API key by hashing the raw key value.
func (s *store) RegisterAPIKey(rawKey, userID string) {
	hash := HashSecret(rawKey)
	ak := &APIKey{
		KeyHash:   hash,
		UserID:    userID,
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	s.apiKeys[hash] = ak
	s.mu.Unlock()

	if s.persist != nil {
		if err := s.persist.SaveAPIKey(hash, *ak); err != nil && s.logger != nil {
			s.logger.Warn("persisting API key", slog.String("error", err.Error()))
		}
	}
}

// ValidateAPIKey checks if a raw API key is registered.
func (s *store) ValidateAPIKey(rawKey string) *APIKey {
	hash := HashSecret(rawKey)

	s.mu.RLock()
	ak := s.apiKeys[hash]
	s.mu.RUnlock()

	return ak
}

// RevokeAPIKey removes an API key by its hash.
func (s *store) RevokeAPIKey(keyHash string) {
	s.mu.Lock()
	delete(s.apiKeys, keyHash)
	s.mu.Unlock()

	if s.persist != nil {
		_ = s.persist.DeleteAPIKey(keyHash)
	}
}

// ListAPIKeys returns all registered API keys.
func (s *store) ListAPIKeys() []*APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]*APIKey, 0, len(s.apiKeys))
	for _, ak := range s.apiKeys {
		keys = append(keys, ak)
	}

	return keys
}

// ReconcileClients removes any persisted pre-configured clients not present
// in the provided set of current client IDs. Returns the number removed.
func (s *store) ReconcileClients(currentClientIDs map[string]struct{}) int {
	s.mu.Lock()

	var stale []string

	for id, client := range s.clients {
		if _, ok := currentClientIDs[id]; ok {
			continue
		}

		if len(client.GrantTypes) == 1 && client.GrantTypes[0] == "client_credentials" {
			stale = append(stale, id)
		}
	}

	for _, id := range stale {
		delete(s.clients, id)
	}

	s.mu.Unlock()

	if s.persist != nil {
		for _, id := range stale {
			_ = s.persist.DeleteOAuthClient(id)
		}
	}

	return len(stale)
}

// ReconcileAPIKeys removes any persisted API keys not present in the
// provided set of current key hashes. Returns the number removed.
func (s *store) ReconcileAPIKeys(currentHashes map[string]struct{}) int {
	s.mu.Lock()

	var stale []string

	for hash := range s.apiKeys {
		if _, ok := currentHashes[hash]; !ok {
			stale = append(stale, hash)
		}
	}

	for _, hash := range stale {
		delete(s.apiKeys, hash)
	}

	s.mu.Unlock()

	if s.persist != nil {
		for _, hash := range stale {
			_ = s.persist.DeleteAPIKey(hash)
		}
	}

	return len(stale)
}

// ClientAllowsGrant checks whether the client is permitted to use the
// given grant type.
func (s *store) ClientAllowsGrant(clientID, grantType string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[clientID]
	if !ok {
		return false
	}

	grants := client.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}

	for _, g := range grants {
		if g == grantType {
			return true
		}
	}

	return false
}
