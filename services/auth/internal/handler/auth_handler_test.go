package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"uno/services/auth/internal/middleware"
	"uno/services/auth/internal/repository/pg"
	"uno/services/auth/internal/service"
	"uno/services/auth/internal/token"
	"uno/services/auth/utils/testdata"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTest creates a test DB, handler, and router, returning them along with a cleanup function
func setupTest(t *testing.T) (*AuthHandler, *chi.Mux, func()) {
	t.Helper()
	ctx := context.Background()

	// Setup test DB
	db, err := testdata.SetupTestDB(ctx)
	require.NoError(t, err, "failed to setup test DB")

	// Initialize handler
	repo := pg.NewPostgresUserRepository(db.Pool)
	jwt := token.NewJWTManager("secret")
	svc := service.NewAuthService(repo, jwt)
	h := NewAuthHandler(svc)

	// Setup router
	router := chi.NewRouter()
	router.Use(middleware.ErrorHandler)
	router.Post("/register", h.Register)
	router.Post("/login", h.Login)

	cleanup := func() {
		db.Teardown(ctx)
	}

	return h, router, cleanup
}

// Integration tests using a real Postgres DB via testcontainers.
func TestAuthHandler_DB(t *testing.T) {

	t.Run("Register success", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// Make HTTP request to register endpoint
		reqBody := RegisterRequest{Email: "a@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Serve the request
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code, "body: %s", rr.Body.String())

		// Parse response and verify tokens are returned
		var resp RegisterResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
	})

	t.Run("Register email exists", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// First register a user
		reqBody := RegisterRequest{Email: "a@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)

		req1 := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		req1.Header.Set("Content-Type", "application/json")
		rr1 := httptest.NewRecorder()
		router.ServeHTTP(rr1, req1)

		// Second register should fail
		b2, _ := json.Marshal(reqBody)
		req2 := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b2))
		req2.Header.Set("Content-Type", "application/json")
		rr2 := httptest.NewRecorder()
		router.ServeHTTP(rr2, req2)

		assert.Equal(t, http.StatusConflict, rr2.Code)
	})

	t.Run("Login success", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// create a user via HTTP
		regBody := RegisterRequest{Email: "a@b.c", Password: "pass"}
		b, _ := json.Marshal(regBody)
		regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		regReq.Header.Set("Content-Type", "application/json")
		regRR := httptest.NewRecorder()
		router.ServeHTTP(regRR, regReq)

		// login
		loginBody := LoginRequest{Email: "a@b.c", Password: "pass"}
		lb, _ := json.Marshal(loginBody)
		loginReq := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(lb))
		loginReq.Header.Set("Content-Type", "application/json")
		loginRR := httptest.NewRecorder()
		router.ServeHTTP(loginRR, loginReq)

		require.Equal(t, http.StatusOK, loginRR.Code)

		// Parse response and verify tokens are returned
		var resp LoginResponse
		_ = json.Unmarshal(loginRR.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
	})

	t.Run("Login unauthorized", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// Attempt to login with non-existent user
		reqBody := LoginRequest{Email: "missing@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Serve the request
		router.ServeHTTP(rr, req)

		// Should return 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
