package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"uno/services/auth/internal/core/domain"
)

func TestSessionRepo_Create(t *testing.T) {
	ctx := context.Background()
	userRepo := NewUserRepo(testDB.DB)
	sessionRepo := NewSessionRepo(testDB.DB)

	user := &domain.User{
		Email:        "session_create@test.com",
		PasswordHash: "hashed_password",
	}
	createdUser, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	session := &domain.Session{
		UserID:           createdUser.ID,
		RefreshTokenHash: "token_hash_create",
		UserAgent:        "TestAgent/1.0",
		IPAddress:        "127.0.0.1",
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
	}

	created, err := sessionRepo.Create(ctx, session)

	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, createdUser.ID, created.UserID)
	assert.Equal(t, session.RefreshTokenHash, created.RefreshTokenHash)
	assert.False(t, created.CreatedAt.IsZero())
	assert.False(t, created.LastUsedAt.IsZero())
}

func TestSessionRepo_GetByTokenHash(t *testing.T) {
	ctx := context.Background()
	userRepo := NewUserRepo(testDB.DB)
	sessionRepo := NewSessionRepo(testDB.DB)

	user := &domain.User{
		Email:        "session_getbyhash@test.com",
		PasswordHash: "hashed_password",
	}
	createdUser, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	tokenHash := "unique_token_hash_get"
	session := &domain.Session{
		UserID:           createdUser.ID,
		RefreshTokenHash: tokenHash,
		UserAgent:        "TestAgent/1.0",
		IPAddress:        "127.0.0.1",
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
	}

	created, err := sessionRepo.Create(ctx, session)
	require.NoError(t, err)

	found, err := sessionRepo.GetByTokenHash(ctx, tokenHash)

	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, created.UserID, found.UserID)
	assert.Equal(t, tokenHash, found.RefreshTokenHash)
	assert.Nil(t, found.RevokedAt)
}

func TestSessionRepo_GetByTokenHash_NotFound(t *testing.T) {
	ctx := context.Background()
	sessionRepo := NewSessionRepo(testDB.DB)

	_, err := sessionRepo.GetByTokenHash(ctx, "nonexistent_token_hash")

	assert.ErrorIs(t, err, domain.ErrSessionNotFound)
}

func TestSessionRepo_Revoke(t *testing.T) {
	ctx := context.Background()
	userRepo := NewUserRepo(testDB.DB)
	sessionRepo := NewSessionRepo(testDB.DB)

	user := &domain.User{
		Email:        "session_revoke@test.com",
		PasswordHash: "hashed_password",
	}
	createdUser, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	tokenHash := "token_hash_revoke"
	session := &domain.Session{
		UserID:           createdUser.ID,
		RefreshTokenHash: tokenHash,
		UserAgent:        "TestAgent/1.0",
		IPAddress:        "127.0.0.1",
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
	}

	created, err := sessionRepo.Create(ctx, session)
	require.NoError(t, err)

	err = sessionRepo.Revoke(ctx, created.ID)
	require.NoError(t, err)

	found, err := sessionRepo.GetByTokenHash(ctx, tokenHash)

	require.NoError(t, err)
	assert.NotNil(t, found.RevokedAt)
}

func TestSessionRepo_RevokeAllForUser(t *testing.T) {
	ctx := context.Background()
	userRepo := NewUserRepo(testDB.DB)
	sessionRepo := NewSessionRepo(testDB.DB)

	user := &domain.User{
		Email:        "session_revokeall@test.com",
		PasswordHash: "hashed_password",
	}
	createdUser, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	tokenHash1 := "token_hash_revokeall_1"
	session1 := &domain.Session{
		UserID:           createdUser.ID,
		RefreshTokenHash: tokenHash1,
		UserAgent:        "TestAgent/1.0",
		IPAddress:        "127.0.0.1",
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
	}
	_, err = sessionRepo.Create(ctx, session1)
	require.NoError(t, err)

	tokenHash2 := "token_hash_revokeall_2"
	session2 := &domain.Session{
		UserID:           createdUser.ID,
		RefreshTokenHash: tokenHash2,
		UserAgent:        "TestAgent/2.0",
		IPAddress:        "192.168.1.1",
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
	}
	_, err = sessionRepo.Create(ctx, session2)
	require.NoError(t, err)

	err = sessionRepo.RevokeAllForUser(ctx, createdUser.ID)
	require.NoError(t, err)

	found1, err := sessionRepo.GetByTokenHash(ctx, tokenHash1)
	require.NoError(t, err)
	assert.NotNil(t, found1.RevokedAt)

	found2, err := sessionRepo.GetByTokenHash(ctx, tokenHash2)
	require.NoError(t, err)
	assert.NotNil(t, found2.RevokedAt)
}

