package mcpauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	tokenExpiry        = time.Hour
	refreshTokenExpiry = 30 * 24 * time.Hour

	// accessTokenBytes is the number of random bytes used to generate
	// an access token (hex-encoded to twice this length).
	accessTokenBytes = 32

	// refreshTokenBytes is the number of random bytes used to generate
	// a refresh token (hex-encoded to twice this length).
	refreshTokenBytes = 32
)

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Resource     string `json:"resource"`
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// handleToken returns the /oauth/token handler.
func handleToken(s *store, logger *slog.Logger, serverURL, trustedProxyHeader string, users UserAuthenticator) http.HandlerFunc {
	limiter := newTokenRateLimiter()

	// Check once whether the Users implementation supports account checking.
	accountChecker, _ := users.(UserAccountChecker)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		ip := extractIP(r, trustedProxyHeader)
		if limiter.checkIP(ip) {
			logger.Warn("token endpoint rate limited", slog.String("ip", ip))
			writeJSONError(w, http.StatusTooManyRequests, "slow_down", "too many failed attempts, try again later")

			return
		}

		var req tokenRequest

		contentType := r.Header.Get("Content-Type")

		switch {
		case strings.HasPrefix(contentType, "application/json"):
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
				return
			}

		case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"),
			contentType == "":
			if err := r.ParseForm(); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid form data")
				return
			}

			req = tokenRequest{
				GrantType:    r.FormValue("grant_type"),
				Code:         r.FormValue("code"),
				RedirectURI:  r.FormValue("redirect_uri"),
				CodeVerifier: r.FormValue("code_verifier"),
				ClientID:     r.FormValue("client_id"),
				ClientSecret: r.FormValue("client_secret"),
				Resource:     r.FormValue("resource"),
				RefreshToken: r.FormValue("refresh_token"),
			}

		default:
			writeJSONError(w, http.StatusUnsupportedMediaType, "invalid_request", "Content-Type must be application/x-www-form-urlencoded or application/json")
			return
		}

		if basicUser, basicPass, ok := r.BasicAuth(); ok {
			req.ClientID = basicUser
			req.ClientSecret = basicPass
			logger.Debug("token request: client_secret_basic auth",
				slog.String("client_id", req.ClientID),
				slog.String("ip", ip),
			)
		}

		switch req.GrantType {
		case "authorization_code", "refresh_token", "client_credentials":
		default:
			logger.Debug("token request: unsupported grant_type",
				slog.String("grant_type", req.GrantType),
				slog.String("client_id", req.ClientID),
				slog.String("ip", ip),
			)
			writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")

			return
		}

		if limiter.checkLockout(req.ClientID) {
			logger.Warn("token endpoint client locked out",
				slog.String("client_id", req.ClientID))
			writeJSONError(w, http.StatusTooManyRequests, "slow_down", "account locked due to repeated failures")

			return
		}

		if req.GrantType != "refresh_token" && req.GrantType != "client_credentials" && req.ClientID != "" && !s.ClientAllowsGrant(req.ClientID, req.GrantType) {
			logger.Debug("token request: client not authorized for grant_type",
				slog.String("grant_type", req.GrantType),
				slog.String("client_id", req.ClientID),
				slog.String("ip", ip),
			)
			writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is not authorized for this grant type")

			return
		}

		logger.Debug("token request",
			slog.String("grant_type", req.GrantType),
			slog.String("client_id", req.ClientID),
			slog.String("ip", ip),
			slog.String("content_type", contentType),
		)

		switch req.GrantType {
		case "refresh_token":
			handleRefreshToken(w, s, limiter, logger, ip, req, serverURL, accountChecker)
		case "client_credentials":
			handleClientCredentials(w, s, limiter, logger, ip, req, serverURL, accountChecker)
		default:
			handleAuthorizationCode(w, s, limiter, logger, ip, req, serverURL, accountChecker)
		}
	}
}

func handleRefreshToken(w http.ResponseWriter, s *store, limiter *tokenRateLimiter, logger *slog.Logger, ip string, req tokenRequest, serverURL string, accountChecker UserAccountChecker) {
	if req.RefreshToken == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	rt := s.ConsumeRefreshToken(req.RefreshToken, req.ClientID, req.Resource)
	if rt == nil {
		limiter.recordFailure(ip, req.ClientID)
		logger.Debug("refresh token validation failed",
			slog.String("client_id", req.ClientID),
			slog.String("ip", ip),
		)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")

		return
	}

	s.DeleteAccessTokenByRefreshToken(req.RefreshToken)

	// Defense-in-depth: reject refresh if the user has been disabled
	// since the token was issued.
	if accountChecker != nil && rt.UserID != "" {
		active, err := accountChecker.IsAccountActive(context.Background(), rt.UserID)
		if err != nil {
			logger.Error("refresh token: account check failed",
				slog.String("user_id", rt.UserID),
				slog.String("error", err.Error()),
			)
			writeJSONError(w, http.StatusInternalServerError, "server_error", "internal server error")

			return
		}

		if !active {
			logger.Warn("refresh token: user account disabled",
				slog.String("user_id", rt.UserID),
				slog.String("client_id", rt.ClientID),
				slog.String("ip", ip),
			)
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "user account is disabled")

			return
		}
	}

	limiter.clearLockout(req.ClientID)

	resource := rt.Resource
	if resource == "" {
		resource = serverURL
	}

	issueTokenPair(w, s, rt.UserID, resource, rt.Scopes, rt.ClientID)

	logger.Info("refresh token exchanged",
		slog.String("client_id", rt.ClientID),
		slog.String("user_id", rt.UserID),
	)
}

func handleClientCredentials(w http.ResponseWriter, s *store, limiter *tokenRateLimiter, logger *slog.Logger, ip string, req tokenRequest, serverURL string, accountChecker UserAccountChecker) {
	if req.ClientID == "" || req.ClientSecret == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "client_id and client_secret are required")
		return
	}

	if !s.ValidateClientSecret(req.ClientID, req.ClientSecret) {
		limiter.recordFailure(ip, req.ClientID)
		logger.Warn("client_credentials authentication failed",
			slog.String("client_id", req.ClientID),
			slog.String("ip", ip))
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")

		return
	}

	if !s.ClientAllowsGrant(req.ClientID, "client_credentials") {
		logger.Debug("client_credentials grant not allowed for client",
			slog.String("client_id", req.ClientID),
			slog.String("ip", ip),
		)
		writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is not authorized for this grant type")

		return
	}

	limiter.clearLockout(req.ClientID)

	resource := req.Resource
	if resource == "" {
		resource = serverURL
	}

	if resource != "" && !resourceMatches(resource, serverURL) {
		logger.Debug("client_credentials resource mismatch",
			slog.String("client_id", req.ClientID),
			slog.String("resource", req.Resource),
			slog.String("server_url", serverURL),
			slog.String("ip", ip),
		)
		writeJSONError(w, http.StatusBadRequest, "invalid_target", "resource parameter does not match this server")

		return
	}

	userID := req.ClientID
	if client := s.GetClient(req.ClientID); client != nil && client.UserID != "" {
		userID = client.UserID
	}

	if accountChecker != nil && userID != "" {
		active, err := accountChecker.IsAccountActive(context.Background(), userID)
		if err != nil {
			logger.Error("client_credentials: account check failed",
				slog.String("user_id", userID),
				slog.String("error", err.Error()),
			)
			writeJSONError(w, http.StatusInternalServerError, "server_error", "internal server error")

			return
		}

		if !active {
			logger.Warn("client_credentials: user account disabled",
				slog.String("user_id", userID),
				slog.String("client_id", req.ClientID),
				slog.String("ip", ip),
			)
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "user account is disabled")

			return
		}
	}

	issueAccessToken(w, s, userID, resource, nil, req.ClientID)

	logger.Info("client_credentials token issued",
		slog.String("client_id", req.ClientID),
		slog.String("user_id", userID),
	)
}

func handleAuthorizationCode(w http.ResponseWriter, s *store, limiter *tokenRateLimiter, logger *slog.Logger, ip string, req tokenRequest, serverURL string, accountChecker UserAccountChecker) {
	if req.Code == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	ac, replayed := s.ConsumeCode(req.Code)
	if ac == nil {
		limiter.recordFailure(ip, req.ClientID)
		logger.Debug("authorization code not found or expired",
			slog.String("client_id", req.ClientID),
			slog.String("ip", ip),
		)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")

		return
	}

	if replayed {
		// RFC 6819 Section 4.4.1.1: revoke all tokens issued from
		// this code. Only revoke if the request client_id matches so
		// an attacker cannot trigger revocation for an arbitrary client.
		if ac.ClientID == req.ClientID {
			s.RevokeClientTokens(ac.ClientID)
			logger.Warn("authorization code replay detected, tokens revoked",
				slog.String("client_id", ac.ClientID),
				slog.String("ip", ip),
			)
		}

		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "authorization code already used")

		return
	}

	if ac.ClientID != "" && req.ClientID != ac.ClientID {
		logger.Debug("authorization code client_id mismatch",
			slog.String("request_client_id", req.ClientID),
			slog.String("code_client_id", ac.ClientID),
			slog.String("ip", ip),
		)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")

		return
	}

	if ac.RedirectURI != "" && req.RedirectURI != ac.RedirectURI {
		logger.Debug("authorization code redirect_uri mismatch",
			slog.String("client_id", req.ClientID),
			slog.String("request_redirect_uri", req.RedirectURI),
			slog.String("code_redirect_uri", ac.RedirectURI),
			slog.String("ip", ip),
		)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")

		return
	}

	if req.Resource != "" && !resourceMatches(req.Resource, serverURL) {
		writeJSONError(w, http.StatusBadRequest, "invalid_target", "resource parameter does not match this server")
		return
	}

	if ac.Resource != "" && req.Resource != "" && !resourceMatches(req.Resource, ac.Resource) {
		writeJSONError(w, http.StatusBadRequest, "invalid_target", "resource does not match authorization code")
		return
	}

	if ac.CodeChallenge == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "authorization code was issued without PKCE")
		return
	}

	if req.CodeVerifier == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
		return
	}

	if !verifyPKCE(req.CodeVerifier, ac.CodeChallenge) {
		limiter.recordFailure(ip, req.ClientID)
		logger.Debug("PKCE verification failed",
			slog.String("client_id", req.ClientID),
			slog.String("ip", ip),
		)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")

		return
	}

	// Defense-in-depth: reject code exchange if the user has been
	// disabled since the code was issued.
	if accountChecker != nil && ac.UserID != "" {
		active, err := accountChecker.IsAccountActive(context.Background(), ac.UserID)
		if err != nil {
			logger.Error("authorization code exchange: account check failed",
				slog.String("user_id", ac.UserID),
				slog.String("error", err.Error()),
			)
			writeJSONError(w, http.StatusInternalServerError, "server_error", "internal server error")

			return
		}

		if !active {
			logger.Warn("authorization code exchange: user account disabled",
				slog.String("user_id", ac.UserID),
				slog.String("client_id", req.ClientID),
				slog.String("ip", ip),
			)
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "user account is disabled")

			return
		}
	}

	limiter.clearLockout(req.ClientID)

	resource := ac.Resource
	if resource == "" {
		resource = serverURL
	}

	clientID := ac.ClientID
	if clientID == "" {
		clientID = req.ClientID
	}

	issueTokenPair(w, s, ac.UserID, resource, ac.Scopes, clientID)

	logger.Info("authorization code exchanged",
		slog.String("client_id", clientID),
		slog.String("user_id", ac.UserID),
	)
}

// issueTokenPair generates and saves an access/refresh token pair, then
// writes the token response.
func issueTokenPair(w http.ResponseWriter, s *store, userID, resource string, scopes []string, clientID string) {
	accessToken := RandomHex(accessTokenBytes)
	refreshToken := RandomHex(refreshTokenBytes)

	s.SaveToken(&OAuthToken{
		Token:       accessToken,
		Kind:        "access",
		UserID:      userID,
		Resource:    resource,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(tokenExpiry),
		RefreshHash: HashSecret(refreshToken),
		ClientID:    clientID,
	})

	s.SaveToken(&OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    userID,
		Resource:  resource,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(refreshTokenExpiry),
		ClientID:  clientID,
	})

	resp := tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(tokenExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        strings.Join(scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// issueAccessToken generates and saves an access token without a refresh
// token. Used for client_credentials grants.
func issueAccessToken(w http.ResponseWriter, s *store, userID, resource string, scopes []string, clientID string) {
	accessToken := RandomHex(accessTokenBytes)

	s.SaveToken(&OAuthToken{
		Token:     accessToken,
		Kind:      "access",
		UserID:    userID,
		Resource:  resource,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(tokenExpiry),
		ClientID:  clientID,
	})

	resp := tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(tokenExpiry.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}
