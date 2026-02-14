package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"uno/services/auth/internal/repository/pg"
	"uno/services/auth/internal/service"
	"uno/services/auth/internal/token"
	"uno/services/auth/utils/testutils/datacase"
)

// Integration tests using a real Postgres DB via testcontainers.
func TestAuthHandler_DB(t *testing.T) {
	dc := datacase.NewDataCase(t)

	t.Run("Register success", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := service.NewAuthService(repo, jwt)
		h := NewAuthHandler(svc)

		reqBody := RegisterRequest{Email: "a@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		rr := httptest.NewRecorder()

		h.Register(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status: got %d want %d", rr.Code, http.StatusOK)
		}
		var resp RegisterResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp.AccessToken == "" || resp.RefreshToken == "" {
			t.Fatalf("expected non-empty tokens")
		}
	})

	t.Run("Register email exists", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := service.NewAuthService(repo, jwt)
		h := NewAuthHandler(svc)

		// pre-create user via service
		_, _, _ = h.service.Register(context.Background(), "a@b.c", "pass")

		reqBody := RegisterRequest{Email: "a@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		rr := httptest.NewRecorder()

		h.Register(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("Login success", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := service.NewAuthService(repo, jwt)
		h := NewAuthHandler(svc)

		// create a user via service
		_, _, _ = h.service.Register(context.Background(), "a@b.c", "pass")

		reqBody := LoginRequest{Email: "a@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
		rr := httptest.NewRecorder()

		h.Login(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status: got %d want %d", rr.Code, http.StatusOK)
		}
		var resp LoginResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)

		if resp.AccessToken == "" || resp.RefreshToken == "" {
			t.Fatalf("expected non-empty tokens")
		}
	})

	t.Run("Login unauthorized", func(t *testing.T) {
		dc.ResetOnCleanup(t)
		repo := pg.NewPostgresUserRepository(dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := service.NewAuthService(repo, jwt)
		h := NewAuthHandler(svc)

		reqBody := LoginRequest{Email: "missing@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status: got %d want %d", rr.Code, http.StatusUnauthorized)
		}
	})
}
