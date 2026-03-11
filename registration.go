package mcpauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type registrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
}

const (
	// clientIDBytes is the number of random bytes used to generate
	// a client ID during dynamic registration.
	clientIDBytes = 16

	// clientSecretBytes is the number of random bytes used to generate
	// a client secret for confidential clients.
	clientSecretBytes = 32
)

// handleRegistration returns the /oauth/register handler.
func handleRegistration(s *store, logger *slog.Logger, trustedProxyHeader string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ip := extractIP(r, trustedProxyHeader)

		ct := r.Header.Get("Content-Type")
		if ct != "" && !strings.HasPrefix(ct, "application/json") {
			writeJSONError(w, http.StatusUnsupportedMediaType, "invalid_client_metadata", "Content-Type must be application/json")
			return
		}

		if !s.RegistrationAllowed() {
			logger.Debug("DCR: registration rate limited", slog.String("ip", ip))
			writeJSONError(w, http.StatusTooManyRequests, "rate_limit", "too many registration requests, try again later")

			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		var req registrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if len(req.RedirectURIs) == 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
			return
		}

		for _, uri := range req.RedirectURIs {
			if err := validateRedirectScheme(uri); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
				return
			}
		}

		for _, gt := range req.GrantTypes {
			if gt != "authorization_code" && gt != "refresh_token" {
				logger.Debug("DCR: rejected disallowed grant_type",
					slog.String("grant_type", gt),
					slog.String("ip", ip),
				)
				writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", fmt.Sprintf("grant type %q is not available through dynamic registration", gt))

				return
			}
		}

		if req.TokenEndpointAuthMethod != "" &&
			req.TokenEndpointAuthMethod != "none" &&
			req.TokenEndpointAuthMethod != "client_secret_post" &&
			req.TokenEndpointAuthMethod != "client_secret_basic" {
			logger.Debug("DCR: rejected unsupported token_endpoint_auth_method",
				slog.String("auth_method", req.TokenEndpointAuthMethod),
				slog.String("ip", ip),
			)
			writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata",
				fmt.Sprintf("unsupported token_endpoint_auth_method %q", req.TokenEndpointAuthMethod))

			return
		}

		clientID := RandomHex(clientIDBytes)

		grantTypes := req.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code"}
		}

		responseTypes := req.ResponseTypes
		if len(responseTypes) == 0 {
			responseTypes = []string{"code"}
		}

		authMethod := req.TokenEndpointAuthMethod
		if authMethod == "" {
			authMethod = "client_secret_basic"
		}

		var clientSecret string

		var secretHash string

		if authMethod == "client_secret_post" || authMethod == "client_secret_basic" {
			b := make([]byte, clientSecretBytes)
			if _, err := rand.Read(b); err != nil {
				panic("crypto/rand failed: " + err.Error())
			}

			clientSecret = hex.EncodeToString(b)
			secretHash = HashSecret(clientSecret)
		}

		issuedAt := time.Now().Unix()

		ok := s.RegisterClient(&OAuthClient{
			ClientID:                clientID,
			ClientName:              req.ClientName,
			RedirectURIs:            req.RedirectURIs,
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
			TokenEndpointAuthMethod: authMethod,
			SecretHash:              secretHash,
			IssuedAt:                issuedAt,
		})
		if !ok {
			writeJSONError(w, http.StatusServiceUnavailable, "server_error", "maximum number of registered clients reached")
			return
		}

		logger.Info("DCR: client registered",
			slog.String("client_id", clientID),
			slog.String("client_name", req.ClientName),
			slog.String("grant_types", strings.Join(grantTypes, ",")),
			slog.String("auth_method", authMethod),
			slog.String("ip", ip),
		)

		resp := registrationResponse{
			ClientID:                clientID,
			ClientName:              req.ClientName,
			ClientSecret:            clientSecret,
			RedirectURIs:            req.RedirectURIs,
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
			TokenEndpointAuthMethod: authMethod,
			ClientIDIssuedAt:        issuedAt,
		}

		if clientSecret != "" {
			zero := int64(0)
			resp.ClientSecretExpiresAt = &zero
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}
}
