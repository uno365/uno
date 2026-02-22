package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"uno/services/auth/internal/adapter/handler/http/middleware"
	"uno/services/auth/internal/core/domain"
	portmock "uno/services/auth/testdata/mock"
)

const (
	testEmail        = "test@example.com"
	testPassword     = "password123"
	testAccessToken  = "access-token-123"
	testRefreshToken = "refresh-token-456"
)

// helper to create request with JSON body
func newJSONRequest(method, path string, body interface{}) *http.Request {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// helper to wrap handler with error middleware for testing
func wrapWithErrorMiddleware(handler http.HandlerFunc) http.Handler {
	return middleware.ErrorHandler(handler)
}

// ==================== Register Tests ====================

func TestRegister_Success(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	mockService.On("Register", mock.Anything, testEmail, testPassword, mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(testAccessToken, testRefreshToken, nil)

	req := newJSONRequest(http.MethodPost, "/register", domain.RegisterRequest{
		Email:    testEmail,
		Password: testPassword,
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Register).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp domain.RegisterResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, testAccessToken, resp.AccessToken)

	// Check cookie is set
	cookies := rr.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == refreshTokenCookieName {
			refreshCookie = c
			break
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, testRefreshToken, refreshCookie.Value)
	assert.True(t, refreshCookie.HttpOnly)

	mockService.AssertExpectations(t)
}

func TestRegister_MissingEmail(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	req := newJSONRequest(http.MethodPost, "/register", domain.RegisterRequest{
		Email:    "",
		Password: testPassword,
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Register).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "email and password are required")
}

func TestRegister_MissingPassword(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	req := newJSONRequest(http.MethodPost, "/register", domain.RegisterRequest{
		Email:    testEmail,
		Password: "",
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Register).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "email and password are required")
}

func TestRegister_InvalidJSON(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Register).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRegister_EmailExists(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	mockService.On("Register", mock.Anything, testEmail, testPassword, mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return("", "", domain.ErrEmailExists)

	req := newJSONRequest(http.MethodPost, "/register", domain.RegisterRequest{
		Email:    testEmail,
		Password: testPassword,
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Register).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusConflict, rr.Code)

	var resp middleware.ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "conflict", resp.Error)

	mockService.AssertExpectations(t)
}

// ==================== Login Tests ====================

func TestLogin_Success(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	mockService.On("Login", mock.Anything, testEmail, testPassword, mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(testAccessToken, testRefreshToken, nil)

	req := newJSONRequest(http.MethodPost, "/login", domain.LoginRequest{
		Email:    testEmail,
		Password: testPassword,
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Login).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp domain.LoginResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, testAccessToken, resp.AccessToken)

	// Check cookie is set
	cookies := rr.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == refreshTokenCookieName {
			refreshCookie = c
			break
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, testRefreshToken, refreshCookie.Value)

	mockService.AssertExpectations(t)
}

func TestLogin_MissingCredentials(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	req := newJSONRequest(http.MethodPost, "/login", domain.LoginRequest{
		Email:    "",
		Password: "",
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Login).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "email and password are required")
}

func TestLogin_InvalidCredentials(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	mockService.On("Login", mock.Anything, testEmail, testPassword, mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return("", "", domain.ErrInvalidCredentials)

	req := newJSONRequest(http.MethodPost, "/login", domain.LoginRequest{
		Email:    testEmail,
		Password: testPassword,
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Login).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var resp middleware.ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", resp.Error)

	mockService.AssertExpectations(t)
}

func TestLogin_InvalidJSON(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Login).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// ==================== Refresh Tests ====================

func TestRefresh_Success(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	newAccessToken := "new-access-token"
	newRefreshToken := "new-refresh-token"

	mockService.On("Refresh", mock.Anything, testRefreshToken, mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(newAccessToken, newRefreshToken, nil)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  refreshTokenCookieName,
		Value: testRefreshToken,
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Refresh).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp domain.RefreshResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, newAccessToken, resp.AccessToken)

	// Check new cookie is set (rotation)
	cookies := rr.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == refreshTokenCookieName {
			refreshCookie = c
			break
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, newRefreshToken, refreshCookie.Value)

	mockService.AssertExpectations(t)
}

func TestRefresh_MissingCookie(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Refresh).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "refresh token is required")
}

func TestRefresh_EmptyCookie(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  refreshTokenCookieName,
		Value: "",
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Refresh).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "refresh token is required")
}

func TestRefresh_InvalidToken(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	mockService.On("Refresh", mock.Anything, "invalid-token", mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return("", "", domain.ErrInvalidToken)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  refreshTokenCookieName,
		Value: "invalid-token",
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Refresh).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// Cookie should be cleared
	cookies := rr.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == refreshTokenCookieName {
			refreshCookie = c
			break
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, "", refreshCookie.Value)
	assert.True(t, refreshCookie.MaxAge < 0)

	mockService.AssertExpectations(t)
}

func TestRefresh_TokenReuse(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	mockService.On("Refresh", mock.Anything, "reused-token", mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return("", "", domain.ErrTokenReuse)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  refreshTokenCookieName,
		Value: "reused-token",
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Refresh).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var resp middleware.ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", resp.Error)

	mockService.AssertExpectations(t)
}

// ==================== Logout Tests ====================

func TestLogout_Success(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	mockService.On("Logout", mock.Anything, testRefreshToken).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  refreshTokenCookieName,
		Value: testRefreshToken,
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Logout).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)

	// Cookie should be cleared
	cookies := rr.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == refreshTokenCookieName {
			refreshCookie = c
			break
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, "", refreshCookie.Value)
	assert.True(t, refreshCookie.MaxAge < 0)

	mockService.AssertExpectations(t)
}

func TestLogout_NoCookie(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	mockService.On("Logout", mock.Anything, "").Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Logout).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)

	mockService.AssertExpectations(t)
}

func TestLogout_ServiceError(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false)

	// Even if service returns error, logout should succeed (cookie cleared)
	mockService.On("Logout", mock.Anything, testRefreshToken).Return(domain.ErrSessionNotFound)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  refreshTokenCookieName,
		Value: testRefreshToken,
	})
	rr := httptest.NewRecorder()

	// Act
	wrapWithErrorMiddleware(handler.Logout).ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code) // Still succeeds

	// Cookie should still be cleared
	cookies := rr.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == refreshTokenCookieName {
			refreshCookie = c
			break
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, "", refreshCookie.Value)

	mockService.AssertExpectations(t)
}

// ==================== Client Info Tests ====================

func TestGetClientInfo_NoProxyHeaders(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, false) // Don't trust proxy headers

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "TestBrowser/1.0")
	req.Header.Set("X-Forwarded-For", "1.2.3.4") // Should be ignored
	req.RemoteAddr = "192.168.1.1:12345"

	// Act
	userAgent, ipAddress := handler.getClientInfo(req)

	// Assert
	assert.Equal(t, "TestBrowser/1.0", userAgent)
	assert.Equal(t, "192.168.1.1:12345", ipAddress) // Uses RemoteAddr, ignores X-Forwarded-For
}

func TestGetClientInfo_WithProxyHeaders(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, true) // Trust proxy headers

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "TestBrowser/1.0")
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.RemoteAddr = "192.168.1.1:12345"

	// Act
	userAgent, ipAddress := handler.getClientInfo(req)

	// Assert
	assert.Equal(t, "TestBrowser/1.0", userAgent)
	assert.Equal(t, "1.2.3.4", ipAddress) // First IP from X-Forwarded-For
}

func TestGetClientInfo_XRealIP(t *testing.T) {
	// Arrange
	mockService := new(portmock.AuthService)
	handler := NewAuthHandler(mockService, true) // Trust proxy headers

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "TestBrowser/1.0")
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.RemoteAddr = "192.168.1.1:12345"

	// Act
	userAgent, ipAddress := handler.getClientInfo(req)

	// Assert
	assert.Equal(t, "TestBrowser/1.0", userAgent)
	assert.Equal(t, "10.0.0.1", ipAddress) // Uses X-Real-IP
}
