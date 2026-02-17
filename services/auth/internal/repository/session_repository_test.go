package repository

import (
	"context"
	"testing"
	"time"

	"uno/services/auth/internal/domain"
	"uno/services/auth/utils/testdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSessionTest creates a test DB, user repo, session repo, and a test user
func setupSessionTest(t *testing.T) (*SessionRepository, *UserRepository, *domain.User, func()) {
	t.Helper()
	ctx := context.Background()

	db, err := testdata.SetupTestDB(ctx)
	require.NoError(t, err, "failed to setup test DB")

	userRepo := NewUserRepository(db.Pool)
	sessionRepo := NewSessionRepository(db.Pool)

	// Create a test user for session tests
	user := &domain.User{
		Email:        "session-test@example.com",
		PasswordHash: "hash123",
	}
	err = userRepo.Create(ctx, user)
	require.NoError(t, err, "failed to create test user")

	cleanup := func() {
		db.Teardown(ctx)
	}

	return sessionRepo, userRepo, user, cleanup
}

func TestSessionRepository(t *testing.T) {

	t.Run("Create and GetByTokenHash", func(t *testing.T) {
		repo, _, user, cleanup := setupSessionTest(t)
		defer cleanup()

		ctx := context.Background()

		session := &domain.Session{
			UserID:           user.ID,
			RefreshTokenHash: "token-hash-123",
			UserAgent:        "TestAgent/1.0",
			IPAddress:        "192.168.1.1",
			ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		}
		err := repo.Create(ctx, session)
		require.NoError(t, err)

		// Verify session was created with generated fields
		assert.NotEmpty(t, session.ID)
		assert.False(t, session.CreatedAt.IsZero())
		assert.False(t, session.LastUsedAt.IsZero())

		// Fetch by token hash and verify
		got, err := repo.GetByTokenHash(ctx, "token-hash-123")
		require.NoError(t, err)

		assert.Equal(t, session.ID, got.ID)
		assert.Equal(t, user.ID, got.UserID)
		assert.Equal(t, "token-hash-123", got.RefreshTokenHash)
		assert.Equal(t, "TestAgent/1.0", got.UserAgent)
		assert.Equal(t, "192.168.1.1", got.IPAddress)
		assert.Nil(t, got.RevokedAt)
	})

	t.Run("GetByTokenHash not found", func(t *testing.T) {
		repo, _, _, cleanup := setupSessionTest(t)
		defer cleanup()

		ctx := context.Background()

		_, err := repo.GetByTokenHash(ctx, "nonexistent-hash")
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)
	})

	t.Run("UpdateTokenHash", func(t *testing.T) {
		repo, _, user, cleanup := setupSessionTest(t)
		defer cleanup()

		ctx := context.Background()

		// Create initial session
		session := &domain.Session{
			UserID:           user.ID,
			RefreshTokenHash: "old-hash",
			UserAgent:        "TestAgent/1.0",
			IPAddress:        "192.168.1.1",
			ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		}
		err := repo.Create(ctx, session)
		require.NoError(t, err)

		originalLastUsed := session.LastUsedAt

		// Wait a bit to ensure timestamp difference
		time.Sleep(10 * time.Millisecond)

		// Update token hash
		err = repo.UpdateTokenHash(ctx, session.ID, "new-hash")
		require.NoError(t, err)

		// Old hash should not find the session
		_, err = repo.GetByTokenHash(ctx, "old-hash")
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)

		// New hash should find the session
		got, err := repo.GetByTokenHash(ctx, "new-hash")
		require.NoError(t, err)
		assert.Equal(t, session.ID, got.ID)
		assert.Equal(t, "new-hash", got.RefreshTokenHash)
		assert.True(t, got.LastUsedAt.After(originalLastUsed), "last_used_at should be updated")
	})

	t.Run("Revoke", func(t *testing.T) {
		repo, _, user, cleanup := setupSessionTest(t)
		defer cleanup()

		ctx := context.Background()

		session := &domain.Session{
			UserID:           user.ID,
			RefreshTokenHash: "revoke-test-hash",
			UserAgent:        "TestAgent/1.0",
			IPAddress:        "192.168.1.1",
			ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		}
		err := repo.Create(ctx, session)
		require.NoError(t, err)

		// Session should not be revoked initially
		got, err := repo.GetByTokenHash(ctx, "revoke-test-hash")
		require.NoError(t, err)
		assert.Nil(t, got.RevokedAt)

		// Revoke the session
		err = repo.Revoke(ctx, session.ID)
		require.NoError(t, err)

		// Session should now be revoked
		got, err = repo.GetByTokenHash(ctx, "revoke-test-hash")
		require.NoError(t, err)
		assert.NotNil(t, got.RevokedAt)
	})

	t.Run("RevokeAllForUser", func(t *testing.T) {
		repo, userRepo, _, cleanup := setupSessionTest(t)
		defer cleanup()

		ctx := context.Background()

		// Create a second user
		user2 := &domain.User{
			Email:        "user2@example.com",
			PasswordHash: "hash456",
		}
		err := userRepo.Create(ctx, user2)
		require.NoError(t, err)

		// Create sessions for user2
		session1 := &domain.Session{
			UserID:           user2.ID,
			RefreshTokenHash: "user2-session1",
			UserAgent:        "TestAgent/1.0",
			IPAddress:        "192.168.1.1",
			ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		}
		session2 := &domain.Session{
			UserID:           user2.ID,
			RefreshTokenHash: "user2-session2",
			UserAgent:        "TestAgent/2.0",
			IPAddress:        "192.168.1.2",
			ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		}
		err = repo.Create(ctx, session1)
		require.NoError(t, err)
		err = repo.Create(ctx, session2)
		require.NoError(t, err)

		// Revoke all sessions for user2
		err = repo.RevokeAllForUser(ctx, user2.ID)
		require.NoError(t, err)

		// Both sessions should be revoked
		got1, err := repo.GetByTokenHash(ctx, "user2-session1")
		require.NoError(t, err)
		assert.NotNil(t, got1.RevokedAt)

		got2, err := repo.GetByTokenHash(ctx, "user2-session2")
		require.NoError(t, err)
		assert.NotNil(t, got2.RevokedAt)
	})

	t.Run("RevokeAllForUser skips already revoked", func(t *testing.T) {
		repo, userRepo, _, cleanup := setupSessionTest(t)
		defer cleanup()

		ctx := context.Background()

		// Create a user
		user := &domain.User{
			Email:        "skip-revoked@example.com",
			PasswordHash: "hash789",
		}
		err := userRepo.Create(ctx, user)
		require.NoError(t, err)

		// Create and revoke a session
		session := &domain.Session{
			UserID:           user.ID,
			RefreshTokenHash: "already-revoked",
			UserAgent:        "TestAgent/1.0",
			IPAddress:        "192.168.1.1",
			ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		}
		err = repo.Create(ctx, session)
		require.NoError(t, err)

		err = repo.Revoke(ctx, session.ID)
		require.NoError(t, err)

		got, err := repo.GetByTokenHash(ctx, "already-revoked")
		require.NoError(t, err)
		originalRevokedAt := got.RevokedAt

		// Wait a bit
		time.Sleep(10 * time.Millisecond)

		// RevokeAllForUser should not update already revoked sessions
		err = repo.RevokeAllForUser(ctx, user.ID)
		require.NoError(t, err)

		got, err = repo.GetByTokenHash(ctx, "already-revoked")
		require.NoError(t, err)
		assert.Equal(t, originalRevokedAt, got.RevokedAt, "revoked_at should not change for already revoked session")
	})

	t.Run("DeleteByID", func(t *testing.T) {
		repo, _, user, cleanup := setupSessionTest(t)
		defer cleanup()

		ctx := context.Background()

		session := &domain.Session{
			UserID:           user.ID,
			RefreshTokenHash: "delete-test-hash",
			UserAgent:        "TestAgent/1.0",
			IPAddress:        "192.168.1.1",
			ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		}
		err := repo.Create(ctx, session)
		require.NoError(t, err)

		// Session should exist
		_, err = repo.GetByTokenHash(ctx, "delete-test-hash")
		require.NoError(t, err)

		// Delete the session
		err = repo.DeleteByID(ctx, session.ID)
		require.NoError(t, err)

		// Session should no longer exist
		_, err = repo.GetByTokenHash(ctx, "delete-test-hash")
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)
	})
}
