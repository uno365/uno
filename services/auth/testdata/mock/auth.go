package mock

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// AuthService is a mock implementation of port.AuthService
type AuthService struct {
	mock.Mock
}

func (m *AuthService) Register(ctx context.Context, email, password, userAgent, ipAddress string) (string, string, error) {
	args := m.Called(ctx, email, password, userAgent, ipAddress)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *AuthService) Login(ctx context.Context, email, password, userAgent, ipAddress string) (string, string, error) {
	args := m.Called(ctx, email, password, userAgent, ipAddress)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *AuthService) Refresh(ctx context.Context, refreshToken, userAgent, ipAddress string) (string, string, error) {
	args := m.Called(ctx, refreshToken, userAgent, ipAddress)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *AuthService) Logout(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}
