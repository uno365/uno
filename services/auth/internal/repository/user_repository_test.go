package repository

import (
	"context"
	"testing"

	"uno/services/auth/internal/domain"
	"uno/services/auth/utils/testdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTest creates a test DB and repository, returning them along with a cleanup function
func setupTest(t *testing.T) (*UserRepository, func()) {
	t.Helper()
	ctx := context.Background()

	db, err := testdata.SetupTestDB(ctx)
	require.NoError(t, err, "failed to setup test DB")

	repo := NewUserRepository(db.Pool)

	cleanup := func() {
		db.Teardown(ctx)
	}

	return repo, cleanup
}

func TestUserRepository(t *testing.T) {

	t.Run("Create and GetByEmail", func(t *testing.T) {
		repo, cleanup := setupTest(t)
		defer cleanup()

		ctx := context.Background()

		u := &domain.User{
			Email:        "alice@example.com",
			PasswordHash: "hash123",
		}
		err := repo.Create(ctx, u)
		require.NoError(t, err)

		// Fetch by email and verify
		got, err := repo.GetByEmail(ctx, u.Email)
		require.NoError(t, err)

		assert.NotEmpty(t, got.ID)
		assert.Equal(t, u.Email, got.Email)
		assert.Equal(t, u.PasswordHash, got.PasswordHash)
		assert.False(t, got.CreatedAt.IsZero())
	})

	t.Run("GetByEmail not found", func(t *testing.T) {
		repo, cleanup := setupTest(t)
		defer cleanup()

		ctx := context.Background()

		_, err := repo.GetByEmail(ctx, "missing@example.com")
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Create and GetByID", func(t *testing.T) {
		repo, cleanup := setupTest(t)
		defer cleanup()

		ctx := context.Background()

		u := &domain.User{
			Email:        "bob@example.com",
			PasswordHash: "hash456",
		}
		err := repo.Create(ctx, u)
		require.NoError(t, err)

		got, err := repo.GetByID(ctx, u.ID)
		require.NoError(t, err)

		assert.Equal(t, u.ID, got.ID)
		assert.Equal(t, u.Email, got.Email)
		assert.Equal(t, u.PasswordHash, got.PasswordHash)
	})
}
