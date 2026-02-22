// Package repository provides PostgreSQL implementations of repository interfaces.
package repo

import (
	"context"
	"time"

	"github.com/google/uuid"

	"uno/services/auth/internal/adapter/db/postgres"
	"uno/services/auth/internal/core/domain"
)

// UserRepo implements UserRepository using PostgreSQL.
type UserRepo struct {
	db *postgres.DB
}

// NewUserRepo creates a new UserRepo with the given connection pool.
func NewUserRepo(db *postgres.DB) *UserRepo {
	return &UserRepo{db: db}
}

// Create persists a new user to the database, generating a UUID and timestamp.
func (r *UserRepo) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	user.ID = uuid.NewString()
	user.CreatedAt = time.Now()

	_, err := r.db.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, created_at)
		 VALUES ($1, $2, $3, $4)`,
		user.ID, user.Email, user.PasswordHash, user.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetByEmail retrieves a user by their email address.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, email, password_hash, created_at
		 FROM users WHERE email = $1`, email)

	var user domain.User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	return &user, nil
}

// GetByID retrieves a user by their unique identifier.
func (r *UserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, email, password_hash, created_at
		 FROM users WHERE id = $1`, id)

	var user domain.User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	return &user, nil
}
