package mcpauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// HashSecret returns the hex-encoded SHA-256 hash of a secret string.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// RandomHex generates a cryptographically random hex string of the given byte length.
func RandomHex(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}

	return hex.EncodeToString(b)
}

// verifyPKCE checks that SHA256(verifier) matches the challenge (S256 method).
// Uses constant-time comparison to prevent timing side channels.
func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// remoteIP extracts the IP address from r.RemoteAddr, stripping the
// port. Falls back to the raw value if parsing fails.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// extractIP returns the client IP, optionally trusting a proxy header.
func extractIP(r *http.Request, trustedProxyHeader string) string {
	if trustedProxyHeader != "" {
		if val := r.Header.Get(trustedProxyHeader); val != "" {
			if idx := strings.Index(val, ","); idx != -1 {
				val = strings.TrimSpace(val[:idx])
			}

			return strings.TrimSpace(val)
		}
	}

	return remoteIP(r)
}

// resourceMatches compares a client-supplied resource URI against the
// server's canonical URL. It accepts an exact match (ignoring trailing
// slashes) or any URL whose scheme and host match the server's base URL.
// MCP clients typically send the full endpoint URL (e.g. https://host/mcp)
// as the resource, while the server's base URL is just the origin.
func resourceMatches(resource, serverURL string) bool {
	if strings.TrimRight(resource, "/") == strings.TrimRight(serverURL, "/") {
		return true
	}

	r, err := url.Parse(resource)
	if err != nil {
		return false
	}

	s, err := url.Parse(serverURL)
	if err != nil {
		return false
	}

	return r.Scheme == s.Scheme && r.Host == s.Host
}

// validateRedirectURI checks that redirectURI matches one of the client's
// registered redirect_uris. For localhost URIs, prefix matching is used
// so any port and path are accepted (RFC 8252 Section 7.3).
// When a client has no registered redirect URIs, only loopback URIs
// are accepted.
func validateRedirectURI(client *OAuthClient, redirectURI string) bool {
	if len(client.RedirectURIs) == 0 {
		u, err := url.Parse(redirectURI)
		if err != nil {
			return false
		}

		return u.Scheme == "http" && isLoopbackHost(u.Hostname())
	}

	for _, registered := range client.RedirectURIs {
		if redirectURI == registered {
			return true
		}

		if isLocalhostPrefix(registered) && isLoopbackRedirect(redirectURI, registered) {
			return true
		}
	}

	return false
}

// isLocalhostPrefix returns true if the URI is an HTTP loopback prefix
// without a port or path, suitable for prefix matching per RFC 8252.
func isLocalhostPrefix(uri string) bool {
	return uri == "http://127.0.0.1" || uri == "http://[::1]"
}

// isLoopbackHost returns true if the hostname is a literal loopback IP.
// DNS names like "localhost" are excluded per RFC 8252 Section 8.3.
func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1"
}

// isLoopbackRedirect checks if redirectURI is a valid loopback redirect
// matching the registered prefix URI.
func isLoopbackRedirect(redirectURI, registeredPrefix string) bool {
	ru, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}

	pu, err := url.Parse(registeredPrefix)
	if err != nil {
		return false
	}

	return ru.Scheme == pu.Scheme && ru.Hostname() == pu.Hostname()
}

// validateRedirectScheme checks that a redirect URI uses HTTPS or targets
// localhost. Per RFC 8252, native apps may use http://localhost but all
// other redirect URIs must use HTTPS.
func validateRedirectScheme(rawURI string) error {
	u, err := url.Parse(rawURI)
	if err != nil {
		return fmt.Errorf("invalid URI: %s", rawURI)
	}

	if u.Scheme == "https" {
		return nil
	}

	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}

	return fmt.Errorf("redirect_uri must use HTTPS (or http://127.0.0.1): %s", rawURI)
}

// redirectWithError redirects the user-agent back to the client with an
// error response per RFC 6749 Section 4.1.2.1.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, description string) {
	params := url.Values{}
	params.Set("error", errCode)
	params.Set("error_description", description)

	if state != "" {
		params.Set("state", state)
	}

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}

	http.Redirect(w, r, redirectURI+sep+params.Encode(), http.StatusFound)
}

// writeJSONError writes a JSON error response per OAuth 2.0 conventions.
func writeJSONError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
