// Package repository provides PostgreSQL implementations of data access interfaces.
package repo

import (
	// Standard library imports
	"context"
	"time"

	// Third-party imports
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	// Local imports
	"uno/services/auth/internal/adapter/db/postgres"
	"uno/services/auth/internal/core/domain"
)

// SessionRepo implements session data access using PostgreSQL.
type SessionRepo struct {
	db *postgres.DB
}

// NewSessionRepo creates a new SessionRepo with the given connection pool.
func NewSessionRepo(db *postgres.DB) *SessionRepo {
	return &SessionRepo{db: db}
}

// Create persists a new session to the database, generating a UUID and timestamps.
func (r *SessionRepo) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	session.ID = uuid.NewString()
	session.CreatedAt = time.Now()
	session.LastUsedAt = time.Now()

	_, err := r.db.Exec(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, created_at, last_used_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		session.ID, session.UserID, session.RefreshTokenHash, session.UserAgent, session.IPAddress,
		session.CreatedAt, session.LastUsedAt, session.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}

	return session, nil

}

// GetByTokenHash retrieves a session by its refresh token hash.
func (r *SessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, user_id, refresh_token_hash, user_agent, ip_address, created_at, last_used_at, expires_at, revoked_at
		 FROM sessions WHERE refresh_token_hash = $1`, tokenHash)

	var session domain.Session
	err := row.Scan(
		&session.ID, &session.UserID, &session.RefreshTokenHash,
		&session.UserAgent, &session.IPAddress, &session.CreatedAt,
		&session.LastUsedAt, &session.ExpiresAt, &session.RevokedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, domain.ErrSessionNotFound
		}
		return nil, err
	}

	return &session, nil
}

// Revoke marks a session as revoked.
func (r *SessionRepo) Revoke(ctx context.Context, sessionID string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = $1 WHERE id = $2`,
		now, sessionID,
	)
	return err
}

// RevokeAllForUser revokes all sessions for a given user (security measure on reuse detection).
func (r *SessionRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`,
		now, userID,
	)
	return err
}

