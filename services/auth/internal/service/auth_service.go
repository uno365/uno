// Package service implements the business logic for authentication operations.
package service

import (
	"context"
	"time"
	"uno/services/auth/internal/domain"
	"uno/services/auth/internal/repository"
	"uno/services/auth/internal/token"

	"golang.org/x/crypto/bcrypt"
)

// AuthService handles user authentication operations including registration and login.
type AuthService struct {
	userRepo repository.UserRepository
	jwt      *token.JWTManager
}

// NewAuthService creates a new AuthService with the given repository and JWT manager.
func NewAuthService(repo repository.UserRepository, jwt *token.JWTManager) *AuthService {
	return &AuthService{userRepo: repo, jwt: jwt}
}

// Register creates a new user account and returns access and refresh tokens.
func (s *AuthService) Register(ctx context.Context, email, password string) (string, string, error) {
	// Check if email already exists
	_, err := s.userRepo.GetByEmail(ctx, email)
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

	err = s.userRepo.Create(ctx, user)
	if err != nil {
		return "", "", err
	}

	// Generate tokens
	accessToken, _ := s.jwt.Generate(user.ID, 15*time.Minute)
	refreshToken, _ := s.jwt.Generate(user.ID, 7*24*time.Hour)

	return accessToken, refreshToken, nil
}

// Login authenticates a user and returns access and refresh tokens.
func (s *AuthService) Login(ctx context.Context, email, password string) (string, string, error) {
	// Find user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return "", "", domain.ErrInvalidCredentials
	}
	// Compare password
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return "", "", domain.ErrInvalidCredentials
	}
	// Generate tokens
	accessToken, _ := s.jwt.Generate(user.ID, 15*time.Minute)
	refreshToken, _ := s.jwt.Generate(user.ID, 7*24*time.Hour)

	return accessToken, refreshToken, nil
}
