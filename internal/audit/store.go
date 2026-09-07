// Package audit records every tool call to SQLite, redacted and off the
// request path.
package audit

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type Row struct {
	ID         int64  `json:"id"`
	TS         int64  `json:"ts"`
	Namespace  string `json:"namespace"`
	Server     string `json:"server"`
	Tool       string `json:"tool"`
	ClientID   string `json:"client_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	ArgsJSON   string `json:"args_json,omitempty"`
	ResultSize int64  `json:"result_size"`
	ResultJSON string `json:"result_json,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// a single connection avoids SQLITE_BUSY between the writer and readers
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Insert(ctx context.Context, r Row) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO tool_calls
		(ts, namespace, server, tool, client_id, session_id, args_json, result_size, result_json, duration_ms, status, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.TS, r.Namespace, r.Server, r.Tool, nullable(r.ClientID), nullable(r.SessionID), nullable(r.ArgsJSON),
		r.ResultSize, nullable(r.ResultJSON), r.DurationMS, r.Status, nullable(r.Error))
	return err
}

type Filter struct {
	Namespace string
	Server    string
	Tool      string
	Status    string
	Since     time.Time
	AfterID   int64
	Limit     int
}

// Query returns rows newest first, or oldest first when AfterID is set
// (the tail-follow case).
func (s *Store) Query(ctx context.Context, f Filter) ([]Row, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if f.Namespace != "" {
		add("namespace = ?", f.Namespace)
	}
	if f.Server != "" {
		add("server = ?", f.Server)
	}
	if f.Tool != "" {
		add("tool = ?", f.Tool)
	}
	if f.Status != "" {
		add("status = ?", f.Status)
	}
	if !f.Since.IsZero() {
		add("ts >= ?", f.Since.UnixMilli())
	}
	order := "ORDER BY id DESC"
	if f.AfterID > 0 {
		add("id > ?", f.AfterID)
		order = "ORDER BY id ASC"
	}
	q := "SELECT id, ts, namespace, server, tool, client_id, session_id, args_json, result_size, result_json, duration_ms, status, error FROM tool_calls"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q += " " + order + " LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		var clientID, sessionID, argsJSON, resultJSON, errStr sql.NullString
		var resultSize sql.NullInt64
		if err := rows.Scan(&r.ID, &r.TS, &r.Namespace, &r.Server, &r.Tool, &clientID, &sessionID, &argsJSON,
			&resultSize, &resultJSON, &r.DurationMS, &r.Status, &errStr); err != nil {
			return nil, err
		}
		r.ClientID, r.SessionID, r.ArgsJSON, r.ResultJSON, r.Error = clientID.String, sessionID.String, argsJSON.String, resultJSON.String, errStr.String
		r.ResultSize = resultSize.Int64
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prune deletes rows older than before and reclaims space.
func (s *Store) Prune(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM tool_calls WHERE ts < ?", before.UnixMilli())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
			return n, fmt.Errorf("vacuum: %w", err)
		}
	}
	return n, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
