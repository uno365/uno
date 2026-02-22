//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"uno/services/auth/internal/core/domain"
	"uno/services/auth/testdata"
)

var integrationServer *Server

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Create postgres container
	pgContainer, err := testdata.CreatePostgresContainer(ctx)

	if err != nil {
		panic("failed to get connection string: " + err.Error())
	}

	// Setup server
	integrationServer = CreateNewServer()
	integrationServer.DATABASE_URL = pgContainer.ConnectionString
	integrationServer.JWT_SECRET = "test-jwt-secret-for-integration"
	integrationServer.CORS_ORIGINS = []string{"*"}
	integrationServer.TRUST_PROXY = false

	integrationServer.MountDB()
	integrationServer.MountMiddlewares()
	integrationServer.MountHandlers()

	code := m.Run()

	integrationServer.DB.Close()
	pgContainer.Container.Terminate(ctx)
	os.Exit(code)
}

// Helper to extract refresh token cookie from response
func getRefreshTokenCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "refresh_token" {
			return cookie
		}
	}
	return nil
}

// Helper to add refresh token cookie to request
func addRefreshTokenCookie(req *http.Request, token string) {
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: token,
	})
}

func TestIntegration_Register_Success(t *testing.T) {
	body, _ := json.Marshal(domain.RegisterRequest{
		Email:    "register_success@test.com",
		Password: "password123",
	})

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp domain.AuthResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)

	// Check refresh token cookie is set
	cookie := getRefreshTokenCookie(rec)
	require.NotNil(t, cookie)
	assert.NotEmpty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
}

func TestIntegration_Register_DuplicateEmail(t *testing.T) {
	// First registration
	body, _ := json.Marshal(domain.RegisterRequest{
		Email:    "duplicate@test.com",
		Password: "password123",
	})

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	// Second registration with same email
	req = httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestIntegration_Register_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body domain.RegisterRequest
	}{
		{"missing email", domain.RegisterRequest{Password: "password123"}},
		{"missing password", domain.RegisterRequest{Email: "test@test.com"}},
		{"missing both", domain.RegisterRequest{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			integrationServer.Router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

func TestIntegration_Login_Success(t *testing.T) {
	// First register
	email := "login_success@test.com"
	password := "password123"

	regBody, _ := json.Marshal(domain.RegisterRequest{Email: email, Password: password})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	// Then login
	loginBody, _ := json.Marshal(domain.LoginRequest{Email: email, Password: password})
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp domain.AuthResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)

	// Check refresh token cookie is set
	cookie := getRefreshTokenCookie(rec)
	require.NotNil(t, cookie)
	assert.NotEmpty(t, cookie.Value)
}

func TestIntegration_Login_WrongPassword(t *testing.T) {
	// First register
	email := "wrong_pass@test.com"
	regBody, _ := json.Marshal(domain.RegisterRequest{Email: email, Password: "correctpassword"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	// Login with wrong password
	loginBody, _ := json.Marshal(domain.LoginRequest{Email: email, Password: "wrongpassword"})
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIntegration_Login_UserNotFound(t *testing.T) {
	loginBody, _ := json.Marshal(domain.LoginRequest{
		Email:    "notfound@test.com",
		Password: "password123",
	})

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIntegration_Refresh_Success(t *testing.T) {
	// Register and get tokens
	email := "refresh_success@test.com"
	regBody, _ := json.Marshal(domain.RegisterRequest{Email: email, Password: "password123"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	refreshCookie := getRefreshTokenCookie(rec)
	require.NotNil(t, refreshCookie)

	// Refresh tokens using cookie
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	addRefreshTokenCookie(req, refreshCookie.Value)
	rec = httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp domain.AuthResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)

	// Check new refresh token cookie is set (rotation)
	newCookie := getRefreshTokenCookie(rec)
	require.NotNil(t, newCookie)
	assert.NotEmpty(t, newCookie.Value)
	assert.NotEqual(t, refreshCookie.Value, newCookie.Value)
}

func TestIntegration_Refresh_MissingCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestIntegration_Refresh_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	addRefreshTokenCookie(req, "invalid-refresh-token")
	rec := httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIntegration_Logout_Success(t *testing.T) {
	// Register and get tokens
	email := "logout_success@test.com"
	regBody, _ := json.Marshal(domain.RegisterRequest{Email: email, Password: "password123"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	refreshCookie := getRefreshTokenCookie(rec)
	require.NotNil(t, refreshCookie)

	// Logout
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	addRefreshTokenCookie(req, refreshCookie.Value)
	rec = httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify cookie is cleared (MaxAge should be -1 or expired)
	clearedCookie := getRefreshTokenCookie(rec)
	require.NotNil(t, clearedCookie)
	assert.True(t, clearedCookie.MaxAge < 0 || clearedCookie.Value == "")

	// Try to refresh with the same token - should fail
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	addRefreshTokenCookie(req, refreshCookie.Value)
	rec = httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIntegration_Logout_WithoutCookie(t *testing.T) {
	// Logout without cookie should still succeed
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()

	integrationServer.Router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestIntegration_FullFlow(t *testing.T) {
	email := "fullflow@test.com"
	password := "password123"

	// 1. Register
	regBody, _ := json.Marshal(domain.RegisterRequest{Email: email, Password: password})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var registerResp domain.AuthResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&registerResp))
	assert.NotEmpty(t, registerResp.AccessToken)
	registerCookie := getRefreshTokenCookie(rec)
	require.NotNil(t, registerCookie)
	t.Log("Registered successfully")

	// 2. Login
	loginBody, _ := json.Marshal(domain.LoginRequest{Email: email, Password: password})
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var loginResp domain.AuthResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&loginResp))
	assert.NotEmpty(t, loginResp.AccessToken)
	loginCookie := getRefreshTokenCookie(rec)
	require.NotNil(t, loginCookie)
	t.Log("Logged in successfully")

	// 3. Refresh
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	addRefreshTokenCookie(req, loginCookie.Value)
	rec = httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var refreshResp domain.AuthResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&refreshResp))
	assert.NotEmpty(t, refreshResp.AccessToken)
	refreshCookie := getRefreshTokenCookie(rec)
	require.NotNil(t, refreshCookie)
	t.Log("Refreshed tokens successfully")

	// 4. Logout
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	addRefreshTokenCookie(req, refreshCookie.Value)
	rec = httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	t.Log("Logged out successfully")

	// 5. Verify tokens no longer work
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	addRefreshTokenCookie(req, refreshCookie.Value)
	rec = httptest.NewRecorder()
	integrationServer.Router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	t.Log("Verified tokens invalidated after logout")
}
