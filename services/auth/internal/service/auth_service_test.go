package service

import (
	"context"
	"testing"
	"uno/services/auth/internal/domain"
	"uno/services/auth/internal/repository/pg"
	"uno/services/auth/internal/token"
	"uno/services/auth/utils/testutils/datacase"

	"golang.org/x/crypto/bcrypt"
)

// Integration tests using a real Postgres DB via testcontainers.
func TestAuthService_DB(t *testing.T) {
	dc := datacase.NewDataCase(t)

	t.Run("Register creates user and tokens", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := NewAuthService(repo, jwt)

		access, refresh, err := svc.Register(context.Background(), "new@example.com", "pass")
		if err != nil {
			t.Fatalf("Register error: %v", err)
		}
		if access == "" || refresh == "" {
			t.Fatalf("expected non-empty tokens")
		}
		// Verify user persisted and password hashed
		u, uerr := repo.GetByEmail(context.Background(), "new@example.com")
		if uerr != nil || u == nil {
			t.Fatalf("expected user to be created: %v", uerr)
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("pass")) != nil {
			t.Fatalf("expected stored password to be a valid bcrypt hash")
		}
	})

	t.Run("Register duplicate email", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := NewAuthService(repo, jwt)

		_, _, _ = svc.Register(context.Background(), "dup@example.com", "pass")
		_, _, err := svc.Register(context.Background(), "dup@example.com", "pass")
		if err == nil || err != domain.ErrEmailExists {
			t.Fatalf("expected ErrEmailExists, got: %v", err)
		}
	})

	t.Run("Login success", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := NewAuthService(repo, jwt)

		_, _, _ = svc.Register(context.Background(), "u@example.com", "pass")
		access, refresh, err := svc.Login(context.Background(), "u@example.com", "pass")
		if err != nil {
			t.Fatalf("Login error: %v", err)
		}
		if access == "" || refresh == "" {
			t.Fatalf("expected non-empty tokens")
		}
	})

	t.Run("Login invalid password", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := NewAuthService(repo, jwt)

		_, _, _ = svc.Register(context.Background(), "u@example.com", "pass")
		_, _, err := svc.Login(context.Background(), "u@example.com", "wrong")
		if err == nil || err != domain.ErrInvalidCredentials {
			t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("Login unknown email", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := NewAuthService(repo, jwt)

		_, _, err := svc.Login(context.Background(), "missing@example.com", "pass")
		if err == nil || err != domain.ErrInvalidCredentials {
			t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
		}
	})
}
