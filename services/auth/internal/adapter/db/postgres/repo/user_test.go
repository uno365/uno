package repo

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"uno/services/auth/internal/core/domain"
	"uno/services/auth/testdata"
)

var testDB *testdata.TestDB

func TestMain(m *testing.M) {
	ctx := context.Background()

	var err error
	testDB, err = testdata.SetupTestDB(ctx)
	if err != nil {
		panic("failed to setup test database: " + err.Error())
	}

	code := m.Run()

	testDB.Teardown(ctx)

	os.Exit(code)
}

func TestUserRepo_Create(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepo(testDB.DB)

	user := &domain.User{
		Email:        "create@test.com",
		PasswordHash: "hashed_password_123",
	}

	created, err := repo.Create(ctx, user)

	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, user.Email, created.Email)
	assert.Equal(t, user.PasswordHash, created.PasswordHash)
	assert.False(t, created.CreatedAt.IsZero())
}

func TestUserRepo_Create_DuplicateEmail(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepo(testDB.DB)

	user := &domain.User{
		Email:        "duplicate@test.com",
		PasswordHash: "hashed_password",
	}

	_, err := repo.Create(ctx, user)
	require.NoError(t, err)

	user2 := &domain.User{
		Email:        "duplicate@test.com",
		PasswordHash: "another_hash",
	}

	_, err = repo.Create(ctx, user2)
	assert.Error(t, err)
}

func TestUserRepo_GetByEmail(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepo(testDB.DB)

	user := &domain.User{
		Email:        "getbyemail@test.com",
		PasswordHash: "hashed_password",
	}

	created, err := repo.Create(ctx, user)
	require.NoError(t, err)

	found, err := repo.GetByEmail(ctx, user.Email)

	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, created.Email, found.Email)
	assert.Equal(t, created.PasswordHash, found.PasswordHash)
}

func TestUserRepo_GetByEmail_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepo(testDB.DB)

	_, err := repo.GetByEmail(ctx, "nonexistent@test.com")

	assert.ErrorIs(t, err, domain.ErrUserNotFound)
}

func TestUserRepo_GetByID(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepo(testDB.DB)

	user := &domain.User{
		Email:        "getbyid@test.com",
		PasswordHash: "hashed_password",
	}

	created, err := repo.Create(ctx, user)
	require.NoError(t, err)

	found, err := repo.GetByID(ctx, created.ID)

	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, created.Email, found.Email)
	assert.Equal(t, created.PasswordHash, found.PasswordHash)
}

func TestUserRepo_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepo(testDB.DB)

	_, err := repo.GetByID(ctx, "nonexistent-uuid")

	assert.ErrorIs(t, err, domain.ErrUserNotFound)
}
