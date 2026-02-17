package service

import (
	"context"
	"testing"
	"uno/services/auth/internal/domain"
	"uno/services/auth/internal/repository"
	"uno/services/auth/internal/token"
	"uno/services/auth/utils/testdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// setupTest creates a test DB, repositories, and auth service, returning them along with a cleanup function
func setupTest(t *testing.T) (*AuthService, *repository.UserRepository, *repository.SessionRepository, func()) {
	t.Helper()
	ctx := context.Background()

	db, err := testdata.SetupTestDB(ctx)
	require.NoError(t, err, "failed to setup test DB")

	userRepo := repository.NewUserRepository(db.Pool)
	sessionRepo := repository.NewSessionRepository(db.Pool)
	jwt := token.NewJWTManager("secret")
	svc := NewAuthService(userRepo, sessionRepo, jwt)

	cleanup := func() {
		db.Teardown(ctx)
	}

	return svc, userRepo, sessionRepo, cleanup
}

func TestAuthService(t *testing.T) {

	t.Run("Register creates user and tokens", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, userRepo, _, cleanup := setupTest(t)
		defer cleanup()

		// Call Register
		access, refresh, err := svc.Register(context.Background(), "new@example.com", "pass", "TestAgent", "127.0.0.1")
		require.NoError(t, err)
		assert.NotEmpty(t, access)
		assert.NotEmpty(t, refresh)

		// Verify user persisted and password hashed
		u, err := userRepo.GetByEmail(context.Background(), "new@example.com")
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("pass")))
	})

	t.Run("Register duplicate email", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Create initial user
		_, _, _ = svc.Register(context.Background(), "dup@example.com", "pass", "TestAgent", "127.0.0.1")
		_, _, err := svc.Register(context.Background(), "dup@example.com", "pass", "TestAgent", "127.0.0.1")
		assert.ErrorIs(t, err, domain.ErrEmailExists)
	})

	t.Run("Login success", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to test login functionality with a real DB
		_, _, _ = svc.Register(context.Background(), "u@example.com", "pass", "TestAgent", "127.0.0.1")
		access, refresh, err := svc.Login(context.Background(), "u@example.com", "pass", "TestAgent", "127.0.0.1")

		// Should succeed and return tokens
		require.NoError(t, err)
		assert.NotEmpty(t, access)
		assert.NotEmpty(t, refresh)
	})

	t.Run("Login invalid password", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to test login with invalid password
		_, _, _ = svc.Register(context.Background(), "u@example.com", "pass", "TestAgent", "127.0.0.1")
		_, _, err := svc.Login(context.Background(), "u@example.com", "wrong", "TestAgent", "127.0.0.1")

		// Should return invalid credentials error
		assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	})

	t.Run("Login unknown email", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Attempt to login with non-existent email
		_, _, err := svc.Login(context.Background(), "missing@example.com", "pass", "TestAgent", "127.0.0.1")

		// Should return invalid credentials error
		assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	})

	t.Run("RefreshToken success", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to get a valid refresh token
		_, refresh, err := svc.Register(context.Background(), "refresh@example.com", "pass", "TestAgent", "127.0.0.1")
		require.NoError(t, err)

		// Call RefreshToken with the valid refresh token
		newAccess, newRefresh, err := svc.RefreshToken(context.Background(), refresh, "TestAgent", "127.0.0.1")

		// Should succeed and return new tokens
		require.NoError(t, err)
		assert.NotEmpty(t, newAccess)
		assert.NotEmpty(t, newRefresh)
	})

	t.Run("RefreshToken invalid token", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Attempt to refresh with an invalid token
		_, _, err := svc.RefreshToken(context.Background(), "invalid-token", "TestAgent", "127.0.0.1")

		// Should return invalid token error
		assert.ErrorIs(t, err, domain.ErrInvalidToken)
	})

	t.Run("RefreshToken rotation works", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to get a valid refresh token
		_, refresh1, err := svc.Register(context.Background(), "rotate@example.com", "pass", "TestAgent", "127.0.0.1")
		require.NoError(t, err)

		// First refresh should work
		_, refresh2, err := svc.RefreshToken(context.Background(), refresh1, "TestAgent", "127.0.0.1")
		require.NoError(t, err)
		assert.NotEqual(t, refresh1, refresh2, "refresh token should be rotated")

		// Second refresh with new token should work
		_, refresh3, err := svc.RefreshToken(context.Background(), refresh2, "TestAgent", "127.0.0.1")
		require.NoError(t, err)
		assert.NotEqual(t, refresh2, refresh3, "refresh token should be rotated again")
	})

	t.Run("RefreshToken reuse detection", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to get a valid refresh token
		_, refresh1, err := svc.Register(context.Background(), "reuse@example.com", "pass", "TestAgent", "127.0.0.1")
		require.NoError(t, err)

		// First refresh should work and rotate the token
		_, refresh2, err := svc.RefreshToken(context.Background(), refresh1, "TestAgent", "127.0.0.1")
		require.NoError(t, err)

		// Attempting to reuse old token should trigger reuse detection
		_, _, err = svc.RefreshToken(context.Background(), refresh1, "TestAgent", "127.0.0.1")
		assert.ErrorIs(t, err, domain.ErrTokenReuse, "reusing old token should trigger reuse detection")

		// The new token should also be revoked (all sessions revoked on reuse)
		_, _, err = svc.RefreshToken(context.Background(), refresh2, "TestAgent", "127.0.0.1")
		assert.ErrorIs(t, err, domain.ErrTokenReuse, "new token should also be revoked after reuse detection")
	})

	t.Run("Logout success", func(t *testing.T) {

		// Setup test DB, repository, and auth service
		svc, _, _, cleanup := setupTest(t)
		defer cleanup()

		// Register user first to get a valid refresh token
		_, refresh, err := svc.Register(context.Background(), "logout@example.com", "pass", "TestAgent", "127.0.0.1")
		require.NoError(t, err)

		// Logout should succeed
		err = svc.Logout(context.Background(), refresh)
		require.NoError(t, err)

		// Attempting to refresh after logout should fail
		_, _, err = svc.RefreshToken(context.Background(), refresh, "TestAgent", "127.0.0.1")
		assert.Error(t, err, "refresh after logout should fail")
	})
}
