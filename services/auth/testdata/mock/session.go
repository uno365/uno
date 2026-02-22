package mock

import (
	"context"
	"github.com/stretchr/testify/mock"
	"uno/services/auth/internal/core/domain"
)

// SessionRepo is a mock implementation of port.SessionRepo
type SessionRepo struct {
	mock.Mock
}

func (m *SessionRepo) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	args := m.Called(ctx, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *SessionRepo) Revoke(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *SessionRepo) GetByTokenHash(ctx context.Context, refreshTokenHash string) (*domain.Session, error) {
	args := m.Called(ctx, refreshTokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *SessionRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}
