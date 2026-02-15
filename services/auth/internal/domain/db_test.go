package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserZeroValue(t *testing.T) {
	var user User
	assert.Empty(t, user.ID)
	assert.Empty(t, user.Email)
	assert.Empty(t, user.PasswordHash)
	assert.True(t, user.CreatedAt.IsZero())
}

func TestUserFieldsAssignment(t *testing.T) {
	now := time.Now()
	user := User{ID: "abc", Email: "a@b.c", PasswordHash: "ph", CreatedAt: now}
	assert.Equal(t, "abc", user.ID)
	assert.Equal(t, "a@b.c", user.Email)
	assert.Equal(t, "ph", user.PasswordHash)
	assert.False(t, user.CreatedAt.IsZero())
}
