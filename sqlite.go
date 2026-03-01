package mcpauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// schemaVersion is the current version of the mcpauth schema.
// Bump this when adding migrations.
const schemaVersion = 1

// migrations maps version numbers to the SQL statements that migrate
// from the previous version. Version 1 is the initial schema.
var migrations = map[int][]string{
	1: {
		`CREATE TABLE IF NOT EXISTS mcpauth_tokens (
			token_hash   TEXT PRIMARY KEY,
			kind         TEXT NOT NULL,
			user_id      TEXT NOT NULL,
			client_id    TEXT NOT NULL DEFAULT '',
			resource     TEXT NOT NULL DEFAULT '',
			scopes       TEXT NOT NULL DEFAULT '[]',
			expires_at   TEXT NOT NULL,
			refresh_hash TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS mcpauth_clients (
			client_id                  TEXT PRIMARY KEY,
			client_name                TEXT NOT NULL DEFAULT '',
			redirect_uris              TEXT NOT NULL DEFAULT '[]',
			grant_types                TEXT NOT NULL DEFAULT '[]',
			response_types             TEXT NOT NULL DEFAULT '[]',
			token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
			secret_hash                TEXT NOT NULL DEFAULT '',
			issued_at                  INTEGER NOT NULL DEFAULT 0,
			user_id                    TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS mcpauth_api_keys (
			key_hash   TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
	},
}

// migrate ensures the mcpauth schema is up to date. It creates
// the version tracking table if needed, then applies any pending
// migrations in order.
func migrate(db *sql.DB) error {
	_, err := db.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS mcpauth_schema_version (
		version INTEGER NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("mcpauth: creating schema version table: %w", err)
	}

	var current int

	row := db.QueryRowContext(context.Background(), `SELECT version FROM mcpauth_schema_version LIMIT 1`)
	if err := row.Scan(&current); err != nil {
		// No row means fresh install, start from 0.
		current = 0
	}

	for v := current + 1; v <= schemaVersion; v++ {
		stmts, ok := migrations[v]
		if !ok {
			return fmt.Errorf("mcpauth: missing migration for version %d", v)
		}

		for _, stmt := range stmts {
			if _, err := db.ExecContext(context.Background(), stmt); err != nil {
				return fmt.Errorf("mcpauth: migration %d failed: %w", v, err)
			}
		}
	}

	if current == 0 {
		_, err = db.ExecContext(context.Background(), `INSERT INTO mcpauth_schema_version (version) VALUES (?)`, schemaVersion)
	} else if current < schemaVersion {
		_, err = db.ExecContext(context.Background(), `UPDATE mcpauth_schema_version SET version = ?`, schemaVersion)
	}

	if err != nil {
		return fmt.Errorf("mcpauth: updating schema version: %w", err)
	}

	return nil
}

// CreateTables creates the mcpauth tables if they do not already exist.
// This is called automatically by NewSQLitePersistence. You only need
// to call this directly if you want to set up tables without creating
// a persistence instance.
func CreateTables(db *sql.DB) error {
	return migrate(db)
}

// sqlitePersistence implements Persistence using database/sql with
// SQLite-compatible SQL.
type sqlitePersistence struct {
	db *sql.DB
}

// NewSQLitePersistence returns a Persistence backed by the given
// *sql.DB. It automatically creates or migrates the required tables
// (mcpauth_tokens, mcpauth_clients, mcpauth_api_keys) using a
// separate mcpauth_schema_version table to track schema versions.
// Returns an error if table creation or migration fails.
//
// The implementation uses INSERT OR REPLACE for save operations and
// is safe for concurrent use when the underlying driver supports it.
func NewSQLitePersistence(db *sql.DB) (Persistence, error) {
	if err := migrate(db); err != nil {
		return nil, err
	}

	return &sqlitePersistence{db: db}, nil
}

func (p *sqlitePersistence) SaveOAuthToken(t OAuthToken) error {
	scopes, err := json.Marshal(t.Scopes)
	if err != nil {
		return fmt.Errorf("marshaling scopes: %w", err)
	}

	_, err = p.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO mcpauth_tokens
			(token_hash, kind, user_id, client_id, resource, scopes, expires_at, refresh_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.TokenHash, t.Kind, t.UserID, t.ClientID,
		t.Resource, string(scopes),
		t.ExpiresAt.UTC().Format(time.RFC3339),
		t.RefreshHash,
	)

	return err
}

func (p *sqlitePersistence) DeleteOAuthToken(tokenHash string) error {
	_, err := p.db.ExecContext(context.Background(), `DELETE FROM mcpauth_tokens WHERE token_hash = ?`, tokenHash)
	return err
}

func (p *sqlitePersistence) AllOAuthTokens() ([]OAuthToken, error) {
	rows, err := p.db.QueryContext(context.Background(),
		`SELECT token_hash, kind, user_id, client_id, resource, scopes, expires_at, refresh_hash
		FROM mcpauth_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []OAuthToken

	for rows.Next() {
		var (
			t         OAuthToken
			scopesStr string
			expiresAt string
		)

		if err := rows.Scan(&t.TokenHash, &t.Kind, &t.UserID, &t.ClientID,
			&t.Resource, &scopesStr, &expiresAt, &t.RefreshHash); err != nil {
			return nil, fmt.Errorf("scanning token row: %w", err)
		}

		if scopesStr != "" && scopesStr != "[]" {
			if err := json.Unmarshal([]byte(scopesStr), &t.Scopes); err != nil {
				return nil, fmt.Errorf("unmarshaling scopes: %w", err)
			}
		}

		t.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("parsing expires_at: %w", err)
		}

		tokens = append(tokens, t)
	}

	return tokens, rows.Err()
}

func (p *sqlitePersistence) SaveOAuthClient(c OAuthClient) error {
	redirectURIs, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("marshaling redirect_uris: %w", err)
	}

	grantTypes, err := json.Marshal(c.GrantTypes)
	if err != nil {
		return fmt.Errorf("marshaling grant_types: %w", err)
	}

	responseTypes, err := json.Marshal(c.ResponseTypes)
	if err != nil {
		return fmt.Errorf("marshaling response_types: %w", err)
	}

	_, err = p.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO mcpauth_clients
			(client_id, client_name, redirect_uris, grant_types, response_types,
			 token_endpoint_auth_method, secret_hash, issued_at, user_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ClientID, c.ClientName,
		string(redirectURIs), string(grantTypes), string(responseTypes),
		c.TokenEndpointAuthMethod, c.SecretHash, c.IssuedAt, c.UserID,
	)

	return err
}

func (p *sqlitePersistence) DeleteOAuthClient(clientID string) error {
	_, err := p.db.ExecContext(context.Background(), `DELETE FROM mcpauth_clients WHERE client_id = ?`, clientID)
	return err
}

func (p *sqlitePersistence) AllOAuthClients() ([]OAuthClient, error) {
	rows, err := p.db.QueryContext(context.Background(),
		`SELECT client_id, client_name, redirect_uris, grant_types, response_types,
			token_endpoint_auth_method, secret_hash, issued_at, user_id
		FROM mcpauth_clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []OAuthClient

	for rows.Next() {
		var (
			c             OAuthClient
			redirectURIs  string
			grantTypes    string
			responseTypes string
		)

		if err := rows.Scan(&c.ClientID, &c.ClientName,
			&redirectURIs, &grantTypes, &responseTypes,
			&c.TokenEndpointAuthMethod, &c.SecretHash, &c.IssuedAt, &c.UserID); err != nil {
			return nil, fmt.Errorf("scanning client row: %w", err)
		}

		if redirectURIs != "" && redirectURIs != "[]" {
			if err := json.Unmarshal([]byte(redirectURIs), &c.RedirectURIs); err != nil {
				return nil, fmt.Errorf("unmarshaling redirect_uris: %w", err)
			}
		}

		if grantTypes != "" && grantTypes != "[]" {
			if err := json.Unmarshal([]byte(grantTypes), &c.GrantTypes); err != nil {
				return nil, fmt.Errorf("unmarshaling grant_types: %w", err)
			}
		}

		if responseTypes != "" && responseTypes != "[]" {
			if err := json.Unmarshal([]byte(responseTypes), &c.ResponseTypes); err != nil {
				return nil, fmt.Errorf("unmarshaling response_types: %w", err)
			}
		}

		clients = append(clients, c)
	}

	return clients, rows.Err()
}

func (p *sqlitePersistence) SaveAPIKey(hash string, key APIKey) error {
	_, err := p.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO mcpauth_api_keys (key_hash, user_id, created_at)
		VALUES (?, ?, ?)`,
		hash, key.UserID, key.CreatedAt.UTC().Format(time.RFC3339),
	)

	return err
}

func (p *sqlitePersistence) DeleteAPIKey(hash string) error {
	_, err := p.db.ExecContext(context.Background(), `DELETE FROM mcpauth_api_keys WHERE key_hash = ?`, hash)
	return err
}

func (p *sqlitePersistence) AllAPIKeys() (map[string]APIKey, error) {
	rows, err := p.db.QueryContext(context.Background(), `SELECT key_hash, user_id, created_at FROM mcpauth_api_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make(map[string]APIKey)

	for rows.Next() {
		var (
			hash      string
			ak        APIKey
			createdAt string
		)

		if err := rows.Scan(&hash, &ak.UserID, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning api_key row: %w", err)
		}

		ak.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parsing created_at: %w", err)
		}

		ak.KeyHash = hash
		keys[hash] = ak
	}

	return keys, rows.Err()
}
