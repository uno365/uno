package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWT(t *testing.T) {
	secret := "test-secret"

	jwt := NewJWT(secret)

	assert.NotNil(t, jwt)
	assert.Equal(t, secret, jwt.secret)
}

func TestJWT_Generate(t *testing.T) {
	jwt := NewJWT("test-secret")
	userID := "user-123"
	duration := 15 * time.Minute

	token, err := jwt.Generate(userID, duration)

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWT_Generate_DifferentDurations(t *testing.T) {
	jwt := NewJWT("test-secret")
	userID := "user-123"

	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"1 minute", 1 * time.Minute},
		{"15 minutes", 15 * time.Minute},
		{"1 hour", 1 * time.Hour},
		{"24 hours", 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := jwt.Generate(userID, tt.duration)
			require.NoError(t, err)
			assert.NotEmpty(t, token)
		})
	}
}

func TestJWT_Verify_ValidToken(t *testing.T) {
	jwt := NewJWT("test-secret")
	userID := "user-123"
	duration := 15 * time.Minute

	token, err := jwt.Generate(userID, duration)
	require.NoError(t, err)

	payload, err := jwt.Verify(token)

	require.NoError(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, userID, payload.UserID)
}

func TestJWT_Verify_ExpiredToken(t *testing.T) {
	jwt := NewJWT("test-secret")
	userID := "user-123"
	duration := -1 * time.Minute // Already expired

	token, err := jwt.Generate(userID, duration)
	require.NoError(t, err)

	_, err = jwt.Verify(token)

	assert.Error(t, err)
}

func TestJWT_Verify_InvalidToken(t *testing.T) {
	jwt := NewJWT("test-secret")

	_, err := jwt.Verify("invalid-token")

	assert.Error(t, err)
}

func TestJWT_Verify_WrongSecret(t *testing.T) {
	jwt1 := NewJWT("secret-1")
	jwt2 := NewJWT("secret-2")
	userID := "user-123"

	token, err := jwt1.Generate(userID, 15*time.Minute)
	require.NoError(t, err)

	_, err = jwt2.Verify(token)

	assert.Error(t, err)
}

func TestJWT_Verify_TamperedToken(t *testing.T) {
	jwt := NewJWT("test-secret")
	userID := "user-123"

	token, err := jwt.Generate(userID, 15*time.Minute)
	require.NoError(t, err)

	// Tamper with the signature by modifying characters in the middle
	tamperedToken := token[:len(token)-10] + "XXXXXXXXXX"

	_, err = jwt.Verify(tamperedToken)

	assert.Error(t, err)
}

func TestJWT_Verify_EmptyToken(t *testing.T) {
	jwt := NewJWT("test-secret")

	_, err := jwt.Verify("")

	assert.Error(t, err)
}

func TestJWT_GenerateAndVerify_MultipleUsers(t *testing.T) {
	jwt := NewJWT("test-secret")
	users := []string{"user-1", "user-2", "user-3"}
	duration := 15 * time.Minute

	for _, userID := range users {
		token, err := jwt.Generate(userID, duration)
		require.NoError(t, err)

		payload, err := jwt.Verify(token)
		require.NoError(t, err)
		assert.Equal(t, userID, payload.UserID)
	}
}
