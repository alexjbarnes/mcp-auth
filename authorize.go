package mcpauth

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	codeExpiry = 5 * time.Minute

	// csrfTokenBytes is the number of random bytes used to generate
	// a CSRF token (hex-encoded to twice this length).
	csrfTokenBytes = 16

	// authCodeBytes is the number of random bytes used to generate
	// an authorization code (hex-encoded to twice this length).
	authCodeBytes = 32

	// maxRequestBody is the maximum size of a POST request body.
	maxRequestBody = 64 << 10 // 64 KB
)

// generateCSRFToken creates a random CSRF token bound to specific
// OAuth parameters and stores it.
func generateCSRFToken(s *store, clientID, redirectURI string) string {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}

	token := hex.EncodeToString(b)
	s.SaveCSRF(token, clientID, redirectURI)

	return token
}

// handleAuthorize returns the /oauth/authorize handler.
func handleAuthorize(s *store, users UserAuthenticator, logger *slog.Logger, serverURL, loginTitle, loginSubtitle, trustedProxyHeader string, tmpl *template.Template) http.HandlerFunc {
	limiter := newLoginRateLimiter()

	if tmpl == nil {
		tmpl = loginPage
	}

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAuthorizeGET(w, r, s, logger, serverURL, loginTitle, loginSubtitle, tmpl)
		case http.MethodPost:
			handleAuthorizePOST(w, r, s, users, logger, limiter, serverURL, loginTitle, loginSubtitle, trustedProxyHeader, tmpl)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func handleAuthorizeGET(w http.ResponseWriter, r *http.Request, s *store, logger *slog.Logger, serverURL, loginTitle, loginSubtitle string, tmpl *template.Template) {
	q := r.URL.Query()
	ip := remoteIP(r)

	clientID := q.Get("client_id")
	if clientID == "" {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}

	client := s.GetClient(clientID)
	if client == nil {
		logger.Debug("authorize: unknown client_id",
			slog.String("client_id", clientID),
			slog.String("ip", ip),
		)
		http.Error(w, "unknown client_id", http.StatusBadRequest)

		return
	}

	if !s.ClientAllowsGrant(clientID, "authorization_code") {
		logger.Debug("authorize: client not allowed for authorization_code grant",
			slog.String("client_id", clientID),
			slog.String("ip", ip),
		)
		http.Error(w, "client is not authorized for the authorization code flow", http.StatusBadRequest)

		return
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		if len(client.RedirectURIs) == 1 {
			redirectURI = client.RedirectURIs[0]
		} else {
			http.Error(w, "redirect_uri is required when multiple URIs are registered", http.StatusBadRequest)
			return
		}
	} else if !validateRedirectURI(client, redirectURI) {
		logger.Debug("authorize: redirect_uri rejected",
			slog.String("client_id", clientID),
			slog.String("redirect_uri", redirectURI),
			slog.String("ip", ip),
		)
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)

		return
	}

	responseType := q.Get("response_type")
	state := q.Get("state")

	if responseType != "code" {
		errCode := "unsupported_response_type"
		if responseType == "" {
			errCode = "invalid_request"
		}

		logger.Debug("authorize: invalid response_type",
			slog.String("client_id", clientID),
			slog.String("response_type", responseType),
			slog.String("redirect_uri", redirectURI),
			slog.String("ip", ip),
		)
		redirectWithError(w, r, redirectURI, state, errCode, "response_type must be \"code\"")

		return
	}

	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge is required (PKCE)")
		return
	}

	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "only S256 code_challenge_method is supported")
		return
	}

	resource := q.Get("resource")
	if resource != "" && !resourceMatches(resource, serverURL) {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "resource parameter does not match this server")
		return
	}

	data := LoginData{
		CSRFToken:           generateCSRFToken(s, clientID, redirectURI),
		ClientID:            clientID,
		ClientName:          client.ClientName,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               q.Get("scope"),
		Resource:            resource,
		Title:               loginTitle,
		Subtitle:            loginSubtitle,
	}

	logger.Debug("authorize: login page served",
		slog.String("client_id", clientID),
		slog.String("redirect_uri", redirectURI),
		slog.String("response_type", responseType),
		slog.String("ip", ip),
	)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	_ = tmpl.Execute(w, data)
}

func handleAuthorizePOST(w http.ResponseWriter, r *http.Request, s *store, users UserAuthenticator, logger *slog.Logger, limiter *loginRateLimiter, serverURL, loginTitle, loginSubtitle, trustedProxyHeader string, tmpl *template.Template) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	ip := extractIP(r, trustedProxyHeader)
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	csrfToken := r.FormValue("csrf_token")
	username := r.FormValue("username")
	password := r.FormValue("password")
	resource := r.FormValue("resource")
	scope := r.FormValue("scope")

	client := s.GetClient(clientID)
	if client == nil {
		logger.Debug("authorize POST: unknown client_id",
			slog.String("client_id", clientID),
			slog.String("ip", ip),
		)
		http.Error(w, "unknown client_id", http.StatusBadRequest)

		return
	}

	if redirectURI == "" {
		if len(client.RedirectURIs) == 1 {
			redirectURI = client.RedirectURIs[0]
		} else {
			http.Error(w, "redirect_uri is required when multiple URIs are registered", http.StatusBadRequest)
			return
		}
	} else if !validateRedirectURI(client, redirectURI) {
		logger.Debug("authorize POST: redirect_uri rejected",
			slog.String("client_id", clientID),
			slog.String("redirect_uri", redirectURI),
			slog.String("ip", ip),
		)
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)

		return
	}

	if codeChallenge == "" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge is required (PKCE)")
		return
	}

	if resource != "" && !resourceMatches(resource, serverURL) {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "resource parameter does not match this server")
		return
	}

	if limiter.check(ip) {
		logger.Warn("login rate limited", slog.String("ip", ip))
		http.Error(w, "too many failed login attempts, try again later", http.StatusTooManyRequests)

		return
	}

	if !s.ConsumeCSRF(csrfToken, clientID, redirectURI) {
		logger.Warn("authorize POST: CSRF validation failed",
			slog.String("client_id", clientID),
			slog.String("redirect_uri", redirectURI),
			slog.String("ip", ip),
		)
		http.Error(w, "invalid or expired CSRF token", http.StatusForbidden)

		return
	}

	userID, err := users.ValidateCredentials(r.Context(), username, password)
	if err != nil {
		logger.Error("authorize POST: credential validation error",
			slog.String("username", username),
			slog.String("error", err.Error()),
		)
		http.Error(w, "internal server error", http.StatusInternalServerError)

		return
	}

	if userID == "" {
		logger.Warn("login failed", slog.String("username", username))
		limiter.record(ip)

		data := LoginData{
			CSRFToken:           generateCSRFToken(s, clientID, redirectURI),
			ClientID:            clientID,
			ClientName:          client.ClientName,
			RedirectURI:         redirectURI,
			State:               state,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: r.FormValue("code_challenge_method"),
			Scope:               scope,
			Resource:            resource,
			Error:               "Invalid username or password",
			Title:               loginTitle,
			Subtitle:            loginSubtitle,
		}

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.WriteHeader(http.StatusUnauthorized)
		_ = tmpl.Execute(w, data)

		return
	}

	logger.Info("login successful",
		slog.String("username", username),
		slog.String("client_id", clientID),
		slog.String("redirect_uri", redirectURI),
		slog.String("ip", ip),
	)

	var scopes []string
	if scope != "" {
		scopes = strings.Fields(scope)
	}

	code := RandomHex(authCodeBytes)
	s.SaveCode(&Code{
		Code:          code,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Resource:      resource,
		UserID:        userID,
		Scopes:        scopes,
		ExpiresAt:     time.Now().Add(codeExpiry),
	})

	params := url.Values{}
	params.Set("code", code)

	if state != "" {
		params.Set("state", state)
	}

	if serverURL != "" {
		params.Set("iss", serverURL)
	}

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}

	redirectURL := redirectURI + sep + params.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
