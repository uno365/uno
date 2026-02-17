// Package service implements the business logic for authentication operations.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"time"
	"uno/services/auth/internal/domain"
	"uno/services/auth/internal/repository"
	"uno/services/auth/internal/token"

	"golang.org/x/crypto/bcrypt"
)

const (
	accessTokenDuration  = 15 * time.Minute
	refreshTokenDuration = 7 * 24 * time.Hour
)

// AuthService handles user authentication operations including registration and login.
type AuthService struct {
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
	jwt         *token.JWTManager
}

// NewAuthService creates a new AuthService with the given repositories and JWT manager.
func NewAuthService(userRepo *repository.UserRepository, sessionRepo *repository.SessionRepository, jwt *token.JWTManager) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		jwt:         jwt,
	}
}

// Register creates a new user account and returns access token and refresh token.
// Also creates a session for the refresh token.
func (s *AuthService) Register(ctx context.Context, email, password, userAgent, ipAddress string) (accessToken, refreshToken string, err error) {
	// Check if email already exists
	_, err = s.userRepo.GetByEmail(ctx, email)
	if err == nil {
		return "", "", domain.ErrEmailExists
	}

	// Hash password
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Create user
	user := &domain.User{
		Email:        email,
		PasswordHash: string(hash),
	}

	createErr := s.userRepo.Create(ctx, user)
	if createErr != nil {
		return "", "", createErr
	}

	// Generate tokens and create session
	return s.createSessionAndTokens(ctx, user.ID, userAgent, ipAddress)
}

// Login authenticates a user and returns access token and refresh token.
// Also creates a session for the refresh token.
func (s *AuthService) Login(ctx context.Context, email, password, userAgent, ipAddress string) (accessToken, refreshToken string, err error) {
	// Find user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return "", "", domain.ErrInvalidCredentials
	}

	// Compare password
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return "", "", domain.ErrInvalidCredentials
	}

	// Generate tokens and create session
	return s.createSessionAndTokens(ctx, user.ID, userAgent, ipAddress)
}

// RefreshToken validates a refresh token, rotates it, and returns new tokens.
// Implements reuse detection - if a token is reused, all user sessions are revoked.
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken, userAgent, ipAddress string) (newAccessToken, newRefreshToken string, err error) {
	// Hash the incoming refresh token
	tokenHash := hashToken(refreshToken)

	// Find session by token hash
	session, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		// Token not found - could be reuse of old rotated token
		// We can't determine the user here, so just return invalid token
		return "", "", domain.ErrInvalidToken
	}

	// Check if session is revoked (reuse detection)
	if session.RevokedAt != nil {
		// Token reuse detected! Revoke all sessions for this user
		if err := s.sessionRepo.RevokeAllForUser(ctx, session.UserID); err != nil {
			slog.Error("failed to revoke all sessions after token reuse detection",
				"user_id", session.UserID,
				"error", err)
		}
		return "", "", domain.ErrTokenReuse
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return "", "", domain.ErrInvalidToken
	}

	// Verify user still exists
	_, err = s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		return "", "", domain.ErrInvalidToken
	}

	// Revoke the current session (keep it for reuse detection)
	err = s.sessionRepo.Revoke(ctx, session.ID)
	if err != nil {
		return "", "", err
	}

	// Generate new tokens and create a new session (rotation)
	return s.createSessionAndTokens(ctx, session.UserID, userAgent, ipAddress)
}

// Logout revokes the session associated with the given refresh token.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil // No token to logout
	}

	tokenHash := hashToken(refreshToken)
	session, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		// Session not found, consider already logged out
		return nil
	}

	return s.sessionRepo.Revoke(ctx, session.ID)
}

// createSessionAndTokens generates tokens and creates a session record.
func (s *AuthService) createSessionAndTokens(ctx context.Context, userID, userAgent, ipAddress string) (accessToken, refreshToken string, err error) {
	// Generate access token
	accessToken, err = s.jwt.Generate(userID, accessTokenDuration)
	if err != nil {
		return "", "", err
	}

	// Generate refresh token (random bytes, not JWT)
	refreshToken, err = generateRefreshToken()
	if err != nil {
		return "", "", err
	}

	// Hash refresh token for storage
	tokenHash := hashToken(refreshToken)

	// Create session
	session := &domain.Session{
		UserID:           userID,
		RefreshTokenHash: tokenHash,
		UserAgent:        userAgent,
		IPAddress:        ipAddress,
		ExpiresAt:        time.Now().Add(refreshTokenDuration),
	}

	err = s.sessionRepo.Create(ctx, session)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// generateRefreshToken creates a cryptographically secure random token.
func generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// hashToken creates a SHA-256 hash of the token for secure storage.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
