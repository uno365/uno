package service

import (
	"context"
	"testing"
	"time"
	"uno/services/auth/internal/domain"
	"uno/services/auth/internal/repository"
	"uno/services/auth/internal/token"
	"uno/services/auth/utils/testdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// setupTest creates a test DB, repository, and auth service, returning them along with a cleanup function
func setupTest(t *testing.T) (*AuthService, *repository.UserRepository, func()) {
	t.Helper()
	ctx := context.Background()

	db, err := testdata.SetupTestDB(ctx)
	require.NoError(t, err, "failed to setup test DB")

	repo := repository.NewUserRepository(db.Pool)
	jwt := token.NewJWTManager("secret")
	svc := NewAuthService(repo, jwt)

	cleanup := func() {
		db.Teardown(ctx)
	}

	return svc, repo, cleanup
}

func TestAuthService(t *testing.T) {

	t.Run("Register creates user and tokens", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, repo, cleanup := setupTest(t)
		defer cleanup()

		// Call Register
		access, refresh, err := svc.Register(context.Background(), "new@example.com", "pass")
		require.NoError(t, err)
		assert.NotEmpty(t, access)
		assert.NotEmpty(t, refresh)

		// Verify user persisted and password hashed
		u, err := repo.GetByEmail(context.Background(), "new@example.com")
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("pass")))
	})

	t.Run("Register duplicate email", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, cleanup := setupTest(t)
		defer cleanup()

		// Create initial user
		_, _, _ = svc.Register(context.Background(), "dup@example.com", "pass")
		_, _, err := svc.Register(context.Background(), "dup@example.com", "pass")
		assert.ErrorIs(t, err, domain.ErrEmailExists)
	})

	t.Run("Login success", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to test login functionality with a real DB
		_, _, _ = svc.Register(context.Background(), "u@example.com", "pass")
		access, refresh, err := svc.Login(context.Background(), "u@example.com", "pass")

		// Should succeed and return tokens
		require.NoError(t, err)
		assert.NotEmpty(t, access)
		assert.NotEmpty(t, refresh)
	})

	t.Run("Login invalid password", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to test login with invalid password
		_, _, _ = svc.Register(context.Background(), "u@example.com", "pass")
		_, _, err := svc.Login(context.Background(), "u@example.com", "wrong")

		// Should return invalid credentials error
		assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	})

	t.Run("Login unknown email", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, cleanup := setupTest(t)
		defer cleanup()

		// Attempt to login with non-existent email
		_, _, err := svc.Login(context.Background(), "missing@example.com", "pass")

		// Should return invalid credentials error
		assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	})

	t.Run("RefreshToken success", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to get a valid refresh token
		_, refresh, err := svc.Register(context.Background(), "refresh@example.com", "pass")
		require.NoError(t, err)

		// Call RefreshToken with the valid refresh token
		newAccess, newRefresh, err := svc.RefreshToken(context.Background(), refresh)

		// Should succeed and return new tokens
		require.NoError(t, err)
		assert.NotEmpty(t, newAccess)
		assert.NotEmpty(t, newRefresh)
	})

	t.Run("RefreshToken invalid token", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, cleanup := setupTest(t)
		defer cleanup()

		// Attempt to refresh with an invalid token
		_, _, err := svc.RefreshToken(context.Background(), "invalid-token")

		// Should return invalid token error
		assert.ErrorIs(t, err, domain.ErrInvalidToken)
	})

	t.Run("RefreshToken expired token", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, cleanup := setupTest(t)
		defer cleanup()

		// Create an expired token using a different JWT manager with negative duration
		jwtManager := token.NewJWTManager("secret")
		expiredToken, _ := jwtManager.Generate("some-user-id", -1*time.Hour)

		// Attempt to refresh with expired token
		_, _, err := svc.RefreshToken(context.Background(), expiredToken)

		// Should return invalid token error
		assert.ErrorIs(t, err, domain.ErrInvalidToken)
	})
}
