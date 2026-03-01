# Changes (completed)

All items have been implemented and tested.

## 1. RemoveClient(clientID string)

Direct method to remove a single client by ID.
- `auth.go:205` / `store.go:524`

## 2. NewSQLitePersistence(db *sql.DB) (Persistence, error)

Built-in SQLite persistence adapter. Automatically creates or migrates
tables on construction. Schema versions tracked in a separate
`mcpauth_schema_version` table so consumers using their own migration
system are not affected.

- `sqlite.go` - `NewSQLitePersistence`, `CreateTables`, `migrate`
- Tables: `mcpauth_tokens`, `mcpauth_clients`, `mcpauth_api_keys`, `mcpauth_schema_version`

## 3. OAuthClient.UserID field

Maps client_credentials clients to user accounts.
- `models.go:32`
- Used in `token.go:267-268`

## 4. Account check in client_credentials

UserAccountChecker.IsAccountActive called for client_credentials grants.
- `token.go:271-272`

## 5. Register(mux) helper

Registers all 6 OAuth endpoint handlers in one call.
- `auth.go:230`

## 6. LoginTemplate injection

Custom login page template via Config.LoginTemplate.
- `auth.go:50-53`

## 7. ClientSecretValidator injection

Pluggable client secret validation via Config.ClientSecretValidator.
- `auth.go:55-67`

## 8. Schema versioning for SQLite persistence

NewSQLitePersistence now runs migrations automatically using a
`mcpauth_schema_version` table. Consumers do not need to call
CreateTables separately. Future schema changes are applied
automatically when the library version is bumped.
- `sqlite.go` - `migrate()`, `schemaVersion`, `migrations` map
