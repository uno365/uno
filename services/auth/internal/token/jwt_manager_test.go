package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTGenerateAndVerify(t *testing.T) {
	jwtManager := NewJWTManager("secret")
	tokenString, err := jwtManager.Generate("user-123", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	parsedClaims, err := jwtManager.Verify(tokenString)
	require.NoError(t, err)
	require.NotNil(t, parsedClaims)
	assert.Equal(t, "user-123", parsedClaims.UserID)
	require.NotNil(t, parsedClaims.ExpiresAt)
	assert.True(t, time.Until(parsedClaims.ExpiresAt.Time) > 0)
}

func TestJWTVerifyInvalidSecret(t *testing.T) {
	firstManager := NewJWTManager("secret1")
	secondManager := NewJWTManager("secret2")
	tokenString, err := firstManager.Generate("id", time.Minute)
	require.NoError(t, err)

	_, err = secondManager.Verify(tokenString)
	assert.Error(t, err)
}
