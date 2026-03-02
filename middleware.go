package mcpauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

type contextKey int

const (
	ctxUserID contextKey = iota
	ctxClientID
	ctxRemoteIP
)

// RequestUserID returns the authenticated user ID from the context, or "".
func RequestUserID(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserID).(string)
	return v
}

// WithUserID returns a context with the given user ID set. This is
// primarily useful in tests to simulate an authenticated request
// without going through the middleware.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxUserID, userID)
}

// RequestClientID returns the OAuth client ID from the context, or "".
func RequestClientID(ctx context.Context) string {
	v, _ := ctx.Value(ctxClientID).(string)
	return v
}

// RequestRemoteIP returns the client IP from the context, or "".
func RequestRemoteIP(ctx context.Context) string {
	v, _ := ctx.Value(ctxRemoteIP).(string)
	return v
}

// checkAccountActive verifies the user account is still enabled.
// Returns true if the check passes (or no checker is configured).
// Writes an HTTP error response and returns false when the check fails.
func checkAccountActive(w http.ResponseWriter, r *http.Request, checker UserAccountChecker, logger *slog.Logger, wwwAuthInvalid, userID, ip string) bool {
	if checker == nil {
		return true
	}

	active, err := checker.IsAccountActive(r.Context(), userID)
	if err != nil {
		logger.Error("middleware: account check failed",
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		w.Header().Set("WWW-Authenticate", wwwAuthInvalid)
		w.WriteHeader(http.StatusUnauthorized)

		return false
	}

	if !active {
		logger.Debug("middleware: user account disabled",
			slog.String("user_id", userID),
			slog.String("ip", ip),
		)
		w.Header().Set("WWW-Authenticate", wwwAuthInvalid)
		w.WriteHeader(http.StatusForbidden)

		return false
	}

	return true
}

// authMiddleware returns HTTP middleware that validates Bearer tokens.
// Unauthenticated requests get a 401 with the WWW-Authenticate header
// pointing to the protected resource metadata URL (RFC 9728 Section 5.1).
// Tokens are validated for expiry and audience (RFC 8707).
func authMiddleware(s *store, logger *slog.Logger, serverURL, apiKeyPrefix, trustedProxyHeader string, users UserAuthenticator) func(http.Handler) http.Handler {
	metadataURL := serverURL + "/.well-known/oauth-protected-resource"
	wwwAuthNoToken := fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL)
	wwwAuthInvalid := fmt.Sprintf(`Bearer error="invalid_token", resource_metadata="%s"`, metadataURL)

	// Check once whether the Users implementation supports account checking.
	accountChecker, _ := users.(UserAccountChecker)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")

			ip := extractIP(r, trustedProxyHeader)

			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				logger.Debug("middleware: no bearer token",
					slog.String("ip", ip),
					slog.String("path", r.URL.Path),
				)
				w.Header().Set("WWW-Authenticate", wwwAuthNoToken)
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")

			// API key authentication. When a prefix is configured, only
			// tokens starting with it are checked and an invalid key is a
			// hard 401. When no prefix is set, every token is speculatively
			// checked as an API key and misses fall through to OAuth.
			hasPrefix := apiKeyPrefix != "" && strings.HasPrefix(token, apiKeyPrefix)
			if hasPrefix || apiKeyPrefix == "" {
				ak := s.ValidateAPIKey(token)
				if ak == nil && hasPrefix {
					logger.Debug("middleware: invalid API key",
						slog.String("ip", ip),
						slog.String("path", r.URL.Path),
					)
					w.Header().Set("WWW-Authenticate", wwwAuthInvalid)
					w.WriteHeader(http.StatusUnauthorized)

					return
				}

				if ak != nil {
					if !checkAccountActive(w, r, accountChecker, logger, wwwAuthInvalid, ak.UserID, ip) {
						return
					}

					logger.Debug("middleware: authenticated via API key",
						slog.String("user_id", ak.UserID),
						slog.String("ip", ip),
					)

					ctx := r.Context()
					ctx = context.WithValue(ctx, ctxUserID, ak.UserID)
					ctx = context.WithValue(ctx, ctxClientID, ak.UserID)
					ctx = context.WithValue(ctx, ctxRemoteIP, ip)

					next.ServeHTTP(w, r.WithContext(ctx))

					return
				}
			}

			// OAuth Bearer token authentication.
			ti := s.ValidateToken(token)
			if ti == nil {
				logger.Debug("middleware: invalid bearer token",
					slog.String("ip", ip),
					slog.String("path", r.URL.Path),
				)
				w.Header().Set("WWW-Authenticate", wwwAuthInvalid)
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			// RFC 8707: reject tokens not issued for this resource server.
			if ti.Resource != "" && !resourceMatches(ti.Resource, serverURL) {
				logger.Debug("middleware: token resource mismatch",
					slog.String("token_resource", ti.Resource),
					slog.String("server_url", serverURL),
					slog.String("client_id", ti.ClientID),
					slog.String("ip", ip),
				)
				w.Header().Set("WWW-Authenticate", wwwAuthInvalid)
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			if !checkAccountActive(w, r, accountChecker, logger, wwwAuthInvalid, ti.UserID, ip) {
				return
			}

			logger.Debug("middleware: authenticated via bearer token",
				slog.String("user_id", ti.UserID),
				slog.String("client_id", ti.ClientID),
				slog.String("ip", ip),
			)

			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxUserID, ti.UserID)
			ctx = context.WithValue(ctx, ctxClientID, ti.ClientID)
			ctx = context.WithValue(ctx, ctxRemoteIP, ip)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
