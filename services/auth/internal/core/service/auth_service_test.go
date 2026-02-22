package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"

	"uno/services/auth/internal/core/domain"
	portmock "uno/services/auth/testdata/mock"
)

// Test fixtures
const (
	testEmail     = "test@example.com"
	testPassword  = "password123"
	testUserAgent = "Mozilla/5.0"
	testIPAddress = "127.0.0.1"
	testUserID    = "user-123"
	testSessionID = "session-456"
)

func TestRegister_Success(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	// Email doesn't exist
	mockUserRepo.On("GetByEmail", ctx, testEmail).Return(nil, domain.ErrUserNotFound)

	// User creation succeeds
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(&domain.User{
		ID:    testUserID,
		Email: testEmail,
	}, nil)

	// Token generation succeeds
	mockTokenService.On("Generate", mock.AnythingOfType("string"), accessTokenDuration).Return("access-token", nil)

	// Session creation succeeds
	mockSessionRepo.On("Create", ctx, mock.AnythingOfType("*domain.Session")).Return(&domain.Session{
		ID:     testSessionID,
		UserID: testUserID,
	}, nil)

	// Act
	accessToken, refreshToken, err := service.Register(ctx, testEmail, testPassword, testUserAgent, testIPAddress)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "access-token", accessToken)
	assert.NotEmpty(t, refreshToken)

	mockUserRepo.AssertExpectations(t)
	mockSessionRepo.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	// Email already exists
	mockUserRepo.On("GetByEmail", ctx, testEmail).Return(&domain.User{
		ID:    testUserID,
		Email: testEmail,
	}, nil)

	// Act
	accessToken, refreshToken, err := service.Register(ctx, testEmail, testPassword, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, domain.ErrEmailExists)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)

	mockUserRepo.AssertExpectations(t)
}

func TestRegister_UserCreationFails(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	// Email doesn't exist
	mockUserRepo.On("GetByEmail", ctx, testEmail).Return(nil, domain.ErrUserNotFound)

	// User creation fails
	createErr := errors.New("database error")
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil, createErr)

	// Act
	accessToken, refreshToken, err := service.Register(ctx, testEmail, testPassword, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, createErr)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)

	mockUserRepo.AssertExpectations(t)
}

func TestLogin_Success(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)

	// User exists
	mockUserRepo.On("GetByEmail", ctx, testEmail).Return(&domain.User{
		ID:           testUserID,
		Email:        testEmail,
		PasswordHash: string(passwordHash),
	}, nil)

	// Token generation succeeds
	mockTokenService.On("Generate", testUserID, accessTokenDuration).Return("access-token", nil)

	// Session creation succeeds
	mockSessionRepo.On("Create", ctx, mock.AnythingOfType("*domain.Session")).Return(&domain.Session{
		ID:     testSessionID,
		UserID: testUserID,
	}, nil)

	// Act
	accessToken, refreshToken, err := service.Login(ctx, testEmail, testPassword, testUserAgent, testIPAddress)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "access-token", accessToken)
	assert.NotEmpty(t, refreshToken)

	mockUserRepo.AssertExpectations(t)
	mockSessionRepo.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
}

func TestLogin_UserNotFound(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	// User doesn't exist
	mockUserRepo.On("GetByEmail", ctx, testEmail).Return(nil, domain.ErrUserNotFound)

	// Act
	accessToken, refreshToken, err := service.Login(ctx, testEmail, testPassword, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)

	mockUserRepo.AssertExpectations(t)
}

func TestLogin_InvalidPassword(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)

	// User exists
	mockUserRepo.On("GetByEmail", ctx, testEmail).Return(&domain.User{
		ID:           testUserID,
		Email:        testEmail,
		PasswordHash: string(passwordHash),
	}, nil)

	// Act
	accessToken, refreshToken, err := service.Login(ctx, testEmail, "wrong-password", testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)

	mockUserRepo.AssertExpectations(t)
}

func TestRefresh_Success(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	refreshToken := "test-refresh-token"
	tokenHash := hashToken(refreshToken)

	// Session exists and is valid
	mockSessionRepo.On("GetByTokenHash", ctx, tokenHash).Return(&domain.Session{
		ID:               testSessionID,
		UserID:           testUserID,
		RefreshTokenHash: tokenHash,
		ExpiresAt:        time.Now().Add(time.Hour),
		RevokedAt:        nil,
	}, nil)

	// User exists
	mockUserRepo.On("GetByID", ctx, testUserID).Return(&domain.User{
		ID:    testUserID,
		Email: testEmail,
	}, nil)

	// Session revocation succeeds
	mockSessionRepo.On("Revoke", ctx, testSessionID).Return(nil)

	// Token generation succeeds
	mockTokenService.On("Generate", testUserID, accessTokenDuration).Return("new-access-token", nil)

	// New session creation succeeds
	mockSessionRepo.On("Create", ctx, mock.AnythingOfType("*domain.Session")).Return(&domain.Session{
		ID:     "new-session-id",
		UserID: testUserID,
	}, nil)

	// Act
	newAccessToken, newRefreshToken, err := service.Refresh(ctx, refreshToken, testUserAgent, testIPAddress)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token", newAccessToken)
	assert.NotEmpty(t, newRefreshToken)

	mockUserRepo.AssertExpectations(t)
	mockSessionRepo.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
}

func TestRefresh_TokenNotFound(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	refreshToken := "invalid-refresh-token"
	tokenHash := hashToken(refreshToken)

	// Session not found
	mockSessionRepo.On("GetByTokenHash", ctx, tokenHash).Return(nil, domain.ErrSessionNotFound)

	// Act
	newAccessToken, newRefreshToken, err := service.Refresh(ctx, refreshToken, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, domain.ErrInvalidToken)
	assert.Empty(t, newAccessToken)
	assert.Empty(t, newRefreshToken)

	mockSessionRepo.AssertExpectations(t)
}

func TestRefresh_TokenReuseDetected(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	refreshToken := "reused-refresh-token"
	tokenHash := hashToken(refreshToken)
	revokedAt := time.Now().Add(-time.Hour)

	// Session exists but is revoked (token reuse)
	mockSessionRepo.On("GetByTokenHash", ctx, tokenHash).Return(&domain.Session{
		ID:               testSessionID,
		UserID:           testUserID,
		RefreshTokenHash: tokenHash,
		ExpiresAt:        time.Now().Add(time.Hour),
		RevokedAt:        &revokedAt,
	}, nil)

	// Revoke all sessions for the user
	mockSessionRepo.On("RevokeAllForUser", ctx, testUserID).Return(nil)

	// Act
	newAccessToken, newRefreshToken, err := service.Refresh(ctx, refreshToken, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, domain.ErrTokenReuse)
	assert.Empty(t, newAccessToken)
	assert.Empty(t, newRefreshToken)

	mockSessionRepo.AssertExpectations(t)
}

func TestRefresh_TokenExpired(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	refreshToken := "expired-refresh-token"
	tokenHash := hashToken(refreshToken)

	// Session exists but is expired
	mockSessionRepo.On("GetByTokenHash", ctx, tokenHash).Return(&domain.Session{
		ID:               testSessionID,
		UserID:           testUserID,
		RefreshTokenHash: tokenHash,
		ExpiresAt:        time.Now().Add(-time.Hour), // Expired
		RevokedAt:        nil,
	}, nil)

	// Act
	newAccessToken, newRefreshToken, err := service.Refresh(ctx, refreshToken, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, domain.ErrInvalidToken)
	assert.Empty(t, newAccessToken)
	assert.Empty(t, newRefreshToken)

	mockSessionRepo.AssertExpectations(t)
}

func TestRefresh_UserNotFound(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	refreshToken := "valid-refresh-token"
	tokenHash := hashToken(refreshToken)

	// Session exists and is valid
	mockSessionRepo.On("GetByTokenHash", ctx, tokenHash).Return(&domain.Session{
		ID:               testSessionID,
		UserID:           testUserID,
		RefreshTokenHash: tokenHash,
		ExpiresAt:        time.Now().Add(time.Hour),
		RevokedAt:        nil,
	}, nil)

	// User no longer exists
	mockUserRepo.On("GetByID", ctx, testUserID).Return(nil, domain.ErrUserNotFound)

	// Act
	newAccessToken, newRefreshToken, err := service.Refresh(ctx, refreshToken, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, domain.ErrInvalidToken)
	assert.Empty(t, newAccessToken)
	assert.Empty(t, newRefreshToken)

	mockUserRepo.AssertExpectations(t)
	mockSessionRepo.AssertExpectations(t)
}

func TestLogout_Success(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	refreshToken := "valid-refresh-token"
	tokenHash := hashToken(refreshToken)

	// Session exists
	mockSessionRepo.On("GetByTokenHash", ctx, tokenHash).Return(&domain.Session{
		ID:               testSessionID,
		UserID:           testUserID,
		RefreshTokenHash: tokenHash,
	}, nil)

	// Session revocation succeeds
	mockSessionRepo.On("Revoke", ctx, testSessionID).Return(nil)

	// Act
	err := service.Logout(ctx, refreshToken)

	// Assert
	assert.NoError(t, err)

	mockSessionRepo.AssertExpectations(t)
}

func TestLogout_EmptyToken(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	// Act
	err := service.Logout(ctx, "")

	// Assert
	assert.NoError(t, err)
	// No mock calls expected
}

func TestLogout_SessionNotFound(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	refreshToken := "unknown-refresh-token"
	tokenHash := hashToken(refreshToken)

	// Session not found
	mockSessionRepo.On("GetByTokenHash", ctx, tokenHash).Return(nil, domain.ErrSessionNotFound)

	// Act
	err := service.Logout(ctx, refreshToken)

	// Assert
	assert.NoError(t, err) // Should not return error, consider already logged out

	mockSessionRepo.AssertExpectations(t)
}

func TestRegister_TokenGenerationFails(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	// Email doesn't exist
	mockUserRepo.On("GetByEmail", ctx, testEmail).Return(nil, domain.ErrUserNotFound)

	// User creation succeeds
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(&domain.User{
		ID:    testUserID,
		Email: testEmail,
	}, nil)

	// Token generation fails
	tokenErr := errors.New("token generation error")
	mockTokenService.On("Generate", mock.AnythingOfType("string"), accessTokenDuration).Return("", tokenErr)

	// Act
	accessToken, refreshToken, err := service.Register(ctx, testEmail, testPassword, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, tokenErr)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)

	mockUserRepo.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
}

func TestRegister_SessionCreationFails(t *testing.T) {
	// Arrange
	mockUserRepo := new(portmock.UserRepo)
	mockSessionRepo := new(portmock.SessionRepo)
	mockTokenService := new(portmock.TokenService)

	service := NewAuthService(mockUserRepo, mockSessionRepo, mockTokenService)
	ctx := context.Background()

	// Email doesn't exist
	mockUserRepo.On("GetByEmail", ctx, testEmail).Return(nil, domain.ErrUserNotFound)

	// User creation succeeds
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(&domain.User{
		ID:    testUserID,
		Email: testEmail,
	}, nil)

	// Token generation succeeds
	mockTokenService.On("Generate", mock.AnythingOfType("string"), accessTokenDuration).Return("access-token", nil)

	// Session creation fails
	sessionErr := errors.New("session creation error")
	mockSessionRepo.On("Create", ctx, mock.AnythingOfType("*domain.Session")).Return(nil, sessionErr)

	// Act
	accessToken, refreshToken, err := service.Register(ctx, testEmail, testPassword, testUserAgent, testIPAddress)

	// Assert
	assert.ErrorIs(t, err, sessionErr)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)

	mockUserRepo.AssertExpectations(t)
	mockSessionRepo.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
}
