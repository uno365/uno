package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"uno/services/auth/internal/domain"
	"uno/services/auth/internal/middleware"
	"uno/services/auth/internal/repository"
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
	userRepo := repository.NewUserRepository(db.Pool)
	sessionRepo := repository.NewSessionRepository(db.Pool)
	jwt := token.NewJWTManager("secret")
	svc := service.NewAuthService(userRepo, sessionRepo, jwt)
	h := NewAuthHandler(svc, false) // Don't trust proxy headers in tests

	// Setup router
	router := chi.NewRouter()
	router.Use(middleware.ErrorHandler)
	router.Post("/register", h.Register)
	router.Post("/login", h.Login)
	router.Post("/refresh", h.Refresh)
	router.Post("/logout", h.Logout)

	cleanup := func() {
		db.Teardown(ctx)
	}

	return h, router, cleanup
}

// getRefreshTokenCookie extracts the refresh_token cookie from the response
func getRefreshTokenCookie(rr *httptest.ResponseRecorder) string {
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "refresh_token" {
			return cookie.Value
		}
	}
	return ""
}

// Integration tests using a real Postgres DB via testcontainers.
func TestAuthHandler_DB(t *testing.T) {

	t.Run("Register success", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// Make HTTP request to register endpoint
		reqBody := domain.RegisterRequest{Email: "a@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Serve the request
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code, "body: %s", rr.Body.String())

		// Parse response and verify access token is returned
		var resp domain.RegisterResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp.AccessToken)

		// Verify refresh token is set in cookie
		refreshCookie := getRefreshTokenCookie(rr)
		assert.NotEmpty(t, refreshCookie, "refresh_token cookie should be set")
	})

	t.Run("Register email exists", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// First register a user
		reqBody := domain.RegisterRequest{Email: "a@b.c", Password: "pass"}
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
		regBody := domain.RegisterRequest{Email: "a@b.c", Password: "pass"}
		b, _ := json.Marshal(regBody)
		regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		regReq.Header.Set("Content-Type", "application/json")
		regRR := httptest.NewRecorder()
		router.ServeHTTP(regRR, regReq)

		// login
		loginBody := domain.LoginRequest{Email: "a@b.c", Password: "pass"}
		lb, _ := json.Marshal(loginBody)
		loginReq := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(lb))
		loginReq.Header.Set("Content-Type", "application/json")
		loginRR := httptest.NewRecorder()
		router.ServeHTTP(loginRR, loginReq)

		require.Equal(t, http.StatusOK, loginRR.Code)

		// Parse response and verify access token is returned
		var resp domain.LoginResponse
		_ = json.Unmarshal(loginRR.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp.AccessToken)

		// Verify refresh token is set in cookie
		refreshCookie := getRefreshTokenCookie(loginRR)
		assert.NotEmpty(t, refreshCookie, "refresh_token cookie should be set")
	})

	t.Run("Login unauthorized", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// Attempt to login with non-existent user
		reqBody := domain.LoginRequest{Email: "missing@b.c", Password: "pass"}
		b, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Serve the request
		router.ServeHTTP(rr, req)

		// Should return 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Refresh success", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// First register a user to get a valid refresh token
		regBody := domain.RegisterRequest{Email: "refresh@b.c", Password: "pass"}
		b, _ := json.Marshal(regBody)
		regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		regReq.Header.Set("Content-Type", "application/json")
		regRR := httptest.NewRecorder()
		router.ServeHTTP(regRR, regReq)
		require.Equal(t, http.StatusCreated, regRR.Code)

		// Get refresh token from cookie
		refreshToken := getRefreshTokenCookie(regRR)
		require.NotEmpty(t, refreshToken)

		// Call refresh endpoint with cookie
		refreshReq := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		refreshReq.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
		refreshRR := httptest.NewRecorder()
		router.ServeHTTP(refreshRR, refreshReq)

		require.Equal(t, http.StatusOK, refreshRR.Code)

		// Parse response and verify new access token is returned
		var resp domain.RefreshResponse
		_ = json.Unmarshal(refreshRR.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp.AccessToken)

		// Verify new refresh token is set in cookie (rotation)
		newRefreshCookie := getRefreshTokenCookie(refreshRR)
		assert.NotEmpty(t, newRefreshCookie, "new refresh_token cookie should be set")
		assert.NotEqual(t, refreshToken, newRefreshCookie, "refresh token should be rotated")
	})

	t.Run("Refresh invalid token", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// Attempt to refresh with invalid token
		req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "invalid-token"})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		// Should return 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Refresh missing cookie", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// Attempt to refresh without cookie
		req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		// Should return 400 Bad Request
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Logout success", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// First register a user to get a valid refresh token
		regBody := domain.RegisterRequest{Email: "logout@b.c", Password: "pass"}
		b, _ := json.Marshal(regBody)
		regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		regReq.Header.Set("Content-Type", "application/json")
		regRR := httptest.NewRecorder()
		router.ServeHTTP(regRR, regReq)
		require.Equal(t, http.StatusCreated, regRR.Code)

		// Get refresh token from cookie
		refreshToken := getRefreshTokenCookie(regRR)
		require.NotEmpty(t, refreshToken)

		// Logout
		logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
		logoutReq.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
		logoutRR := httptest.NewRecorder()
		router.ServeHTTP(logoutRR, logoutReq)

		require.Equal(t, http.StatusOK, logoutRR.Code)

		// Verify cookie is cleared (MaxAge < 0)
		for _, cookie := range logoutRR.Result().Cookies() {
			if cookie.Name == "refresh_token" {
				assert.True(t, cookie.MaxAge < 0, "cookie should be cleared")
			}
		}

		// Attempt to refresh after logout should fail
		refreshReq := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		refreshReq.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
		refreshRR := httptest.NewRecorder()
		router.ServeHTTP(refreshRR, refreshReq)

		assert.Equal(t, http.StatusUnauthorized, refreshRR.Code, "refresh after logout should fail")
	})

	t.Run("Token rotation prevents reuse", func(t *testing.T) {

		// Setup test DB, handler, and router
		_, router, cleanup := setupTest(t)
		defer cleanup()

		// First register a user to get a valid refresh token
		regBody := domain.RegisterRequest{Email: "reuse@b.c", Password: "pass"}
		b, _ := json.Marshal(regBody)
		regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
		regReq.Header.Set("Content-Type", "application/json")
		regRR := httptest.NewRecorder()
		router.ServeHTTP(regRR, regReq)
		require.Equal(t, http.StatusCreated, regRR.Code)

		// Get original refresh token
		originalToken := getRefreshTokenCookie(regRR)
		require.NotEmpty(t, originalToken)

		// First refresh should succeed
		refreshReq1 := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		refreshReq1.AddCookie(&http.Cookie{Name: "refresh_token", Value: originalToken})
		refreshRR1 := httptest.NewRecorder()
		router.ServeHTTP(refreshRR1, refreshReq1)
		require.Equal(t, http.StatusOK, refreshRR1.Code)

		// Get new token
		newToken := getRefreshTokenCookie(refreshRR1)
		require.NotEmpty(t, newToken)
		require.NotEqual(t, originalToken, newToken)

		// Attempting to reuse original token should fail
		refreshReq2 := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		refreshReq2.AddCookie(&http.Cookie{Name: "refresh_token", Value: originalToken})
		refreshRR2 := httptest.NewRecorder()
		router.ServeHTTP(refreshRR2, refreshReq2)

		assert.Equal(t, http.StatusUnauthorized, refreshRR2.Code, "reusing old token should fail")
	})
}
