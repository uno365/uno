package port

import (
	"time"

	"uno/services/auth/internal/core/domain"
)

type TokenService interface {
	Generate(userID string, duration time.Duration) (string, error)
	Verify(token string) (*domain.TokenPayload, error)
}
