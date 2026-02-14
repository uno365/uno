package pg

import (
	"context"
	"testing"

	"uno/services/auth/internal/domain"
	"uno/services/auth/internal/repository"
	"uno/services/auth/utils/testutils/datacase"
)

// Compile-time check that PostgresUserRepository implements repository.UserRepository
var _ repository.UserRepository = (*PostgresUserRepository)(nil)

func TestPostgresUserRepository(t *testing.T) {
	// Spin up Postgres, run migrations, and get a pgx pool
	dc := datacase.NewDataCase(t)

	t.Run("Create and GetByEmail", func(t *testing.T) {
		// Ensure DB resets after this subtest
		dc.ResetOnCleanup(t)
		repo := NewPostgresUserRepository(dc.Pool())

		ctx := context.Background()

		u := &domain.User{
			Email:        "alice@example.com",
			PasswordHash: "hash123",
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		// Fetch by email and verify
		got, err := repo.GetByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("GetByEmail failed: %v", err)
		}

		if got.ID == "" {
			t.Fatalf("expected ID to be set")
		}
		if got.Email != u.Email {
			t.Fatalf("expected email %q, got %q", u.Email, got.Email)
		}
		if got.PasswordHash != u.PasswordHash {
			t.Fatalf("expected password hash %q, got %q", u.PasswordHash, got.PasswordHash)
		}
		if got.CreatedAt.IsZero() {
			t.Fatalf("expected CreatedAt to be set")
		}
	})

	t.Run("GetByEmail not found", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := NewPostgresUserRepository(dc.Pool())
		ctx := context.Background()

		_, err := repo.GetByEmail(ctx, "missing@example.com")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if err != domain.ErrUserNotFound {
			t.Fatalf("expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("Create and GetByID", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := NewPostgresUserRepository(dc.Pool())
		ctx := context.Background()

		u := &domain.User{
			Email:        "bob@example.com",
			PasswordHash: "hash456",
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID failed: %v", err)
		}

		if got.ID != u.ID {
			t.Fatalf("expected ID %q, got %q", u.ID, got.ID)
		}
		if got.Email != u.Email {
			t.Fatalf("expected email %q, got %q", u.Email, got.Email)
		}
		if got.PasswordHash != u.PasswordHash {
			t.Fatalf("expected password hash %q, got %q", u.PasswordHash, got.PasswordHash)
		}
	})
}
