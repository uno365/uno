// Package repository defines interfaces for data persistence operations.
package repository

import (
	"context"
	"uno/services/auth/internal/domain"
)

// UserRepository defines the interface for user data persistence operations.
type UserRepository interface {
	// Create persists a new user to the data store.
	Create(ctx context.Context, user *domain.User) error
	// GetByEmail retrieves a user by their email address.
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	// GetByID retrieves a user by their unique identifier.
	GetByID(ctx context.Context, id string) (*domain.User, error)
}
