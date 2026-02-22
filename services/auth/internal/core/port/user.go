package port

import (
	"context"

	"uno/services/auth/internal/core/domain"
)

type UserRepo interface {
	Create(ctx context.Context, user *domain.User) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
}
