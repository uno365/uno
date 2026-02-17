// Package repository provides PostgreSQL implementations of data access interfaces.
package repository

import (
	"context"
	"time"
	"uno/services/auth/internal/domain"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionRepository implements session data access using PostgreSQL.
type SessionRepository struct {
	db *pgxpool.Pool
}

// NewSessionRepository creates a new SessionRepository with the given connection pool.
func NewSessionRepository(db *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create persists a new session to the database, generating a UUID and timestamps.
func (r *SessionRepository) Create(ctx context.Context, session *domain.Session) error {
	session.ID = uuid.NewString()
	session.CreatedAt = time.Now()
	session.LastUsedAt = time.Now()

	_, err := r.db.Exec(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, created_at, last_used_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		session.ID, session.UserID, session.RefreshTokenHash, session.UserAgent, session.IPAddress,
		session.CreatedAt, session.LastUsedAt, session.ExpiresAt,
	)

	return err
}

// GetByTokenHash retrieves a session by its refresh token hash.
func (r *SessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
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

// UpdateTokenHash updates the session's refresh token hash and last used timestamp.
func (r *SessionRepository) UpdateTokenHash(ctx context.Context, sessionID, newTokenHash string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE sessions SET refresh_token_hash = $1, last_used_at = $2 WHERE id = $3`,
		newTokenHash, time.Now(), sessionID,
	)
	return err
}

// Revoke marks a session as revoked.
func (r *SessionRepository) Revoke(ctx context.Context, sessionID string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = $1 WHERE id = $2`,
		now, sessionID,
	)
	return err
}

// RevokeAllForUser revokes all sessions for a given user (security measure on reuse detection).
func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`,
		now, userID,
	)
	return err
}

// DeleteByID deletes a session by its ID.
func (r *SessionRepository) DeleteByID(ctx context.Context, sessionID string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	return err
}
