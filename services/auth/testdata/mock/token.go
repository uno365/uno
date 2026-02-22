package mock

import (
	"time"

	"github.com/stretchr/testify/mock"

	"uno/services/auth/internal/core/domain"
)

// TokenService is a mock implementation of port.TokenService
type TokenService struct {
	mock.Mock
}

func (m *TokenService) Generate(userID string, duration time.Duration) (string, error) {
	args := m.Called(userID, duration)
	return args.String(0), args.Error(1)
}

func (m *TokenService) Verify(token string) (*domain.TokenPayload, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenPayload), args.Error(1)
}
