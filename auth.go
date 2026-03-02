package mcpauth

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
)

// Config holds all configuration for the OAuth 2.1 authorization server.
type Config struct {
	// ServerURL is the public-facing base URL of the server (e.g.
	// "https://example.com"). Used for issuer, metadata endpoints,
	// and audience validation.
	ServerURL string

	// Users validates credentials during the authorization code flow.
	// Required for /oauth/authorize to work.
	Users UserAuthenticator

	// Persist is the durable storage backend. Pass nil for in-memory
	// only operation (useful in tests and single-process deployments).
	Persist Persistence

	// Logger receives structured log output. Defaults to slog.Default()
	// when nil.
	Logger *slog.Logger

	// APIKeyPrefix, when non-empty, enables API key authentication in
	// the middleware. Bearer tokens starting with this prefix are
	// treated as API keys rather than OAuth access tokens.
	APIKeyPrefix string

	// LoginTitle is the heading shown on the login page.
	// Defaults to "Sign In" when empty.
	LoginTitle string

	// LoginSubtitle is the subtitle shown on the login page.
	// Defaults to "Sign in to grant access to your account." when empty.
	LoginSubtitle string

	// GrantTypes lists the grant types advertised in server metadata.
	// Defaults to ["authorization_code", "refresh_token"] when nil.
	GrantTypes []string

	// TrustedProxyHeader, when non-empty, is the HTTP header used to
	// extract the client IP address (e.g. "X-Forwarded-For"). Only set
	// this when the server runs behind a trusted reverse proxy.
	TrustedProxyHeader string

	// LoginTemplate, when non-nil, replaces the built-in login page
	// with a custom template. The template receives a LoginData struct.
	// When nil, the default built-in login page is used.
	LoginTemplate *template.Template

	// ClientSecretValidator, when non-nil, replaces the default SHA-256
	// constant-time comparison used to validate client secrets. This allows
	// callers to use bcrypt or other hashing schemes for stored secrets.
	//
	// The function receives the raw secret from the incoming request and
	// the stored hash from the OAuthClient.SecretHash field. Return true
	// if the secret matches the hash.
	//
	// When nil, the default behavior computes SHA-256(rawSecret) and
	// performs a constant-time comparison against storedHash. This is safe
	// for high-entropy generated secrets but not suitable for user-chosen
	// passwords.
	ClientSecretValidator func(rawSecret, storedHash string) bool
}

// Server is the OAuth 2.1 authorization server. Create one with New()
// and wire its handler methods into your HTTP mux.
type Server struct {
	s                     *store
	logger                *slog.Logger
	serverURL             string
	loginTitle            string
	loginSubtitle         string
	trustedProxyHeader    string
	apiKeyPrefix          string
	grantTypes            []string
	users                 UserAuthenticator
	loginTemplate         *template.Template
	clientSecretValidator func(string, string) bool
}

// New creates a new Server from the given configuration. Call Stop()
// when the server is no longer needed to release background resources.
func New(cfg Config) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	loginTitle := cfg.LoginTitle
	if loginTitle == "" {
		loginTitle = "Sign In"
	}

	loginSubtitle := cfg.LoginSubtitle
	if loginSubtitle == "" {
		loginSubtitle = "Sign in to grant access to your account."
	}

	grantTypes := cfg.GrantTypes
	if grantTypes == nil {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	return &Server{
		s:                     newStore(cfg.Persist, logger, cfg.ClientSecretValidator),
		logger:                logger,
		serverURL:             cfg.ServerURL,
		loginTitle:            loginTitle,
		loginSubtitle:         loginSubtitle,
		trustedProxyHeader:    cfg.TrustedProxyHeader,
		apiKeyPrefix:          cfg.APIKeyPrefix,
		grantTypes:            grantTypes,
		users:                 cfg.Users,
		loginTemplate:         cfg.LoginTemplate,
		clientSecretValidator: cfg.ClientSecretValidator,
	}
}

// Stop releases background resources (GC goroutine). Safe to call
// multiple times.
func (srv *Server) Stop() {
	srv.s.stop()
}

// HandleProtectedResourceMetadata returns a handler for
// GET /.well-known/oauth-protected-resource (RFC 9728).
func (srv *Server) HandleProtectedResourceMetadata() http.HandlerFunc {
	return handleProtectedResourceMetadata(srv.serverURL)
}

// HandleServerMetadata returns a handler for
// GET /.well-known/oauth-authorization-server (RFC 8414).
func (srv *Server) HandleServerMetadata() http.HandlerFunc {
	return handleServerMetadata(srv.serverURL, srv.grantTypes)
}

// HandleRegistration returns a handler for
// POST /oauth/register (RFC 7591 Dynamic Client Registration).
func (srv *Server) HandleRegistration() http.HandlerFunc {
	return handleRegistration(srv.s, srv.logger, srv.trustedProxyHeader)
}

// HandleAuthorize returns a handler for
// GET+POST /oauth/authorize (authorization code flow with PKCE).
func (srv *Server) HandleAuthorize() http.HandlerFunc {
	return handleAuthorize(srv.s, srv.users, srv.logger, srv.serverURL, srv.loginTitle, srv.loginSubtitle, srv.trustedProxyHeader, srv.loginTemplate)
}

// HandleToken returns a handler for
// POST /oauth/token (token exchange and refresh).
func (srv *Server) HandleToken() http.HandlerFunc {
	return handleToken(srv.s, srv.logger, srv.serverURL, srv.trustedProxyHeader, srv.users)
}

// Middleware returns HTTP middleware that validates Bearer tokens
// (both OAuth access tokens and API keys) and injects user/client/IP
// information into the request context. Use RequestUserID(),
// RequestClientID(), and RequestRemoteIP() to extract the values.
func (srv *Server) Middleware() func(http.Handler) http.Handler {
	return authMiddleware(srv.s, srv.logger, srv.serverURL, srv.apiKeyPrefix, srv.trustedProxyHeader, srv.users)
}

// RegisterPreConfiguredClient adds a pre-configured OAuth client that
// survives reconciliation. Use this for server-owned clients that
// should not be removed by ReconcileClients.
//
// Returns an error if the client requests grant types that the server
// does not support.
func (srv *Server) RegisterPreConfiguredClient(client *OAuthClient) error {
	for _, cg := range client.GrantTypes {
		found := false

		for _, sg := range srv.grantTypes {
			if cg == sg {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("client %q requests grant type %q, but server only supports %v", client.ClientID, cg, srv.grantTypes)
		}
	}

	srv.s.RegisterPreConfiguredClient(client)

	return nil
}

// ReconcileClients removes dynamically registered clients whose IDs
// are not in currentClientIDs. Pre-configured clients are never removed.
// Returns the number of clients removed.
func (srv *Server) ReconcileClients(currentClientIDs map[string]struct{}) int {
	return srv.s.ReconcileClients(currentClientIDs)
}

// RegisterAPIKey registers a raw API key string and associates it
// with the given user ID. The key is hashed with SHA-256 before
// storage.
func (srv *Server) RegisterAPIKey(rawKey, userID string) {
	srv.s.RegisterAPIKey(rawKey, userID)
}

// RegisterAPIKeyByHash registers an API key using a pre-computed hash.
// Use this when the raw key is not available and you already hold the
// SHA-256 hash (e.g. from HashSecret).
func (srv *Server) RegisterAPIKeyByHash(hash, userID string) {
	srv.s.RegisterAPIKeyByHash(hash, userID)
}

// ReconcileAPIKeys removes API keys whose hashes are not in
// currentHashes. Returns the number of keys removed.
func (srv *Server) ReconcileAPIKeys(currentHashes map[string]struct{}) int {
	return srv.s.ReconcileAPIKeys(currentHashes)
}

// RevokeAPIKey removes the API key with the given hash.
func (srv *Server) RevokeAPIKey(keyHash string) {
	srv.s.RevokeAPIKey(keyHash)
}

// ListAPIKeys returns all registered API keys.
func (srv *Server) ListAPIKeys() []*APIKey {
	return srv.s.ListAPIKeys()
}

// RemoveClient removes a client by ID. Returns true if the client
// existed and was removed.
func (srv *Server) RemoveClient(clientID string) bool {
	return srv.s.RemoveClient(clientID)
}

// GetClient returns the registered client with the given ID, or nil.
func (srv *Server) GetClient(clientID string) *OAuthClient {
	return srv.s.GetClient(clientID)
}

// ClientAllowsGrant reports whether the given client is permitted to
// use the specified grant type.
func (srv *Server) ClientAllowsGrant(clientID, grantType string) bool {
	return srv.s.ClientAllowsGrant(clientID, grantType)
}

// Register wires all OAuth endpoint handlers onto the given mux:
//
//	GET  /.well-known/oauth-protected-resource
//	GET  /.well-known/oauth-authorization-server
//	POST /oauth/register
//	GET  /oauth/authorize
//	POST /oauth/authorize
//	POST /oauth/token
func (srv *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", srv.HandleProtectedResourceMetadata())
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", srv.HandleServerMetadata())
	mux.HandleFunc("POST /oauth/register", srv.HandleRegistration())
	mux.Handle("GET /oauth/authorize", srv.HandleAuthorize())
	mux.Handle("POST /oauth/authorize", srv.HandleAuthorize())
	mux.HandleFunc("POST /oauth/token", srv.HandleToken())
}
