package mcpauth

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketTokens  = []byte("mcpauth_tokens")
	bucketClients = []byte("mcpauth_clients")
	bucketAPIKeys = []byte("mcpauth_api_keys")
)

// CreateBoltBuckets creates the three buckets used by BoltPersistence if
// they do not already exist. This is called automatically by
// NewBoltPersistence. You only need to call this directly if you want
// to set up buckets without creating a persistence instance.
func CreateBoltBuckets(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketTokens, bucketClients, bucketAPIKeys} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("mcpauth: creating bucket %s: %w", name, err)
			}
		}
		return nil
	})
}

// boltPersistence implements Persistence using bbolt.
type boltPersistence struct {
	db *bolt.DB
}

// NewBoltPersistence returns a Persistence backed by the given *bbolt.DB.
// It automatically creates the required buckets if they do not exist.
// The implementation is safe for concurrent use because bbolt serializes
// write transactions.
func NewBoltPersistence(db *bolt.DB) (Persistence, error) {
	if err := CreateBoltBuckets(db); err != nil {
		return nil, err
	}

	return &boltPersistence{db: db}, nil
}

func (p *boltPersistence) SaveOAuthToken(t OAuthToken) error {
	data, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	return p.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).Put([]byte(t.TokenHash), data)
	})
}

func (p *boltPersistence) DeleteOAuthToken(tokenHash string) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).Delete([]byte(tokenHash))
	})
}

func (p *boltPersistence) AllOAuthTokens() ([]OAuthToken, error) {
	var tokens []OAuthToken

	err := p.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(k, v []byte) error {
			var t OAuthToken
			if err := json.Unmarshal(v, &t); err != nil {
				return fmt.Errorf("unmarshaling token %s: %w", k, err)
			}
			tokens = append(tokens, t)
			return nil
		})
	})

	return tokens, err
}

func (p *boltPersistence) SaveOAuthClient(c OAuthClient) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling client: %w", err)
	}

	return p.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketClients).Put([]byte(c.ClientID), data)
	})
}

func (p *boltPersistence) DeleteOAuthClient(clientID string) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketClients).Delete([]byte(clientID))
	})
}

func (p *boltPersistence) AllOAuthClients() ([]OAuthClient, error) {
	var clients []OAuthClient

	err := p.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketClients).ForEach(func(k, v []byte) error {
			var c OAuthClient
			if err := json.Unmarshal(v, &c); err != nil {
				return fmt.Errorf("unmarshaling client %s: %w", k, err)
			}
			clients = append(clients, c)
			return nil
		})
	})

	return clients, err
}

func (p *boltPersistence) SaveAPIKey(hash string, key APIKey) error {
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("marshaling api key: %w", err)
	}

	return p.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAPIKeys).Put([]byte(hash), data)
	})
}

func (p *boltPersistence) DeleteAPIKey(hash string) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAPIKeys).Delete([]byte(hash))
	})
}

func (p *boltPersistence) AllAPIKeys() (map[string]APIKey, error) {
	keys := make(map[string]APIKey)

	err := p.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAPIKeys).ForEach(func(k, v []byte) error {
			var ak APIKey
			if err := json.Unmarshal(v, &ak); err != nil {
				return fmt.Errorf("unmarshaling api key %s: %w", k, err)
			}
			keys[string(k)] = ak
			return nil
		})
	})

	return keys, err
}
