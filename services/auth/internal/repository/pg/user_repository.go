// Package pg provides PostgreSQL implementations of repository interfaces.
package pg

import (
	"context"
	"time"
	"uno/services/auth/internal/domain"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresUserRepository implements UserRepository using PostgreSQL.
type PostgresUserRepository struct {
	db *pgxpool.Pool
}

// NewPostgresUserRepository creates a new PostgresUserRepository with the given connection pool.
func NewPostgresUserRepository(db *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

// Create persists a new user to the database, generating a UUID and timestamp.
func (r *PostgresUserRepository) Create(ctx context.Context, user *domain.User) error {
	user.ID = uuid.NewString()
	user.CreatedAt = time.Now()

	_, err := r.db.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, created_at)
		 VALUES ($1, $2, $3, $4)`,
		user.ID, user.Email, user.PasswordHash, user.CreatedAt,
	)

	return err
}

// GetByEmail retrieves a user by their email address.
func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
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
func (r *PostgresUserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
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
