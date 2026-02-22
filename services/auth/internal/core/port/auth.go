package port

import (
	"context"
)

type AuthService interface {
	Register(ctx context.Context, email, password, userAgent, ipAddress string) (string, string, error)
	Login(ctx context.Context, email, password, userAgent, ipAddress string) (string, string, error)
	Refresh(ctx context.Context, refreshToken, userAgent, ipAddress string) (string, string, error)
	Logout(ctx context.Context, refreshToken string) error
}
