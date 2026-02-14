package domain

import (
	"testing"
	"time"
)

func TestUserZeroValue(t *testing.T) {
	var user User
	if user.ID != "" || user.Email != "" || user.PasswordHash != "" {
		t.Fatalf("expected zero-value strings, got: %+v", user)
	}
	if !user.CreatedAt.IsZero() {
		t.Fatalf("expected zero time, got: %v", user.CreatedAt)
	}
}

func TestUserFieldsAssignment(t *testing.T) {
	now := time.Now()
	user := User{ID: "abc", Email: "a@b.c", PasswordHash: "ph", CreatedAt: now}
	if user.ID != "abc" || user.Email != "a@b.c" || user.PasswordHash != "ph" {
		t.Fatalf("unexpected field values: %+v", user)
	}
	if user.CreatedAt.IsZero() {
		t.Fatalf("expected non-zero CreatedAt")
	}
}
