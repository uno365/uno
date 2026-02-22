package port

import (
	"context"

	"uno/services/auth/internal/core/domain"
)

type SessionRepo interface {
	Create(ctx context.Context, session *domain.Session) (*domain.Session, error)
	Revoke(ctx context.Context, sessionID string) error
	GetByTokenHash(ctx context.Context, refreshTokenHash string) (*domain.Session, error)
	RevokeAllForUser(ctx context.Context, userID string) error
}
