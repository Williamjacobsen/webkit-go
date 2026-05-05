package authkit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

var ErrSessionExpired = errors.New("session expired")

type SessionStore interface {
	Save(sessionID string, user *User, maxAge int) error
	Load(sessionID string) (*User, error)
	Delete(sessionID string) error
}

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		claims_json TEXT NOT NULL,
		expires_at INTEGER NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Save(sessionID string, user *User, maxAge int) error {
	claimsJSON, err := json.Marshal(user.Claims)
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(time.Duration(maxAge) * time.Second).Unix()

	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO sessions (id, claims_json, expires_at) VALUES (?, ?, ?)`,
		sessionID, string(claimsJSON), expiresAt,
	)
	return err
}

func (s *SQLiteStore) Load(sessionID string) (*User, error) {
	var claimsJSON string
	var expiresAt int64

	err := s.db.QueryRow(
		`SELECT claims_json, expires_at FROM sessions WHERE id = ?`,
		sessionID,
	).Scan(&claimsJSON, &expiresAt)
	if err != nil {
		return nil, err
	}

	if time.Now().Unix() > expiresAt {
		s.Delete(sessionID)
		return nil, ErrSessionExpired
	}

	var claims map[string]any
	if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
		return nil, err
	}

	subject, _ := claims["sub"].(string)

	return &User{
		Subject: subject,
		Claims:  claims,
	}, nil
}

func (s *SQLiteStore) Delete(sessionID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, sessionID)
	return err
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
