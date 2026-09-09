package upstreamauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	_ "modernc.org/sqlite"
)

// Credentials is everything needed to rebuild a refreshing token source
// after a restart: the client registration and the last token.
type Credentials struct {
	ClientID     string           `json:"client_id"`
	ClientSecret string           `json:"client_secret,omitempty"`
	AuthURL      string           `json:"auth_url"`
	TokenURL     string           `json:"token_url"`
	AuthStyle    oauth2.AuthStyle `json:"auth_style"`
	Scopes       []string         `json:"scopes,omitempty"`
	Token        *oauth2.Token    `json:"token"`
}

func (c *Credentials) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID: c.ClientID, ClientSecret: c.ClientSecret, Scopes: c.Scopes,
		Endpoint: oauth2.Endpoint{AuthURL: c.AuthURL, TokenURL: c.TokenURL, AuthStyle: c.AuthStyle},
	}
}

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS upstream_oauth (
		id TEXT PRIMARY KEY, credentials TEXT NOT NULL, updated_at INTEGER NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

var errNotFound = errors.New("no credentials")

func (s *Store) Load(ctx context.Context, id string) (*Credentials, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT credentials FROM upstream_oauth WHERE id = ?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) Save(ctx context.Context, id string, c *Credentials) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO upstream_oauth (id, credentials, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET credentials = excluded.credentials, updated_at = excluded.updated_at`,
		id, string(raw), time.Now().UnixMilli())
	return err
}

// Checkpoint folds the write-ahead log into the main file; see audit.Store.
func (s *Store) Checkpoint(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM upstream_oauth WHERE id = ?", id)
	return err
}
