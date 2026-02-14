// Package handler provides HTTP handlers for authentication endpoints.
package handler

import (
	"net/http"

	"uno/services/auth/internal/service"

	"github.com/gin-gonic/gin"
)

// ================ Type and Constructor ================

// AuthHandler handles HTTP requests for authentication operations.
type AuthHandler struct {
	service *service.AuthService
}

// NewAuthHandler creates a new AuthHandler with the given AuthService.
func NewAuthHandler(s *service.AuthService) *AuthHandler {
	return &AuthHandler{service: s}
}

// ================ Registration ================

// RegisterRequest represents the request body for user registration.
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// RegisterResponse represents the response body for successful registration.
type RegisterResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Register handles user registration requests.
func (handler *AuthHandler) Register(gc *gin.Context) {
	// Parse request body
	var req RegisterRequest
	if err := gc.ShouldBindJSON(&req); err != nil {
		gc.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call service layer to register user
	access, refresh, err := handler.service.Register(gc.Request.Context(), req.Email, req.Password)

	// Handle errors via middleware
	if err != nil {
		_ = gc.Error(err)
		return
	}

	// Write response
	gc.JSON(http.StatusCreated, RegisterResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}

// ================ Login ================

// LoginRequest represents the request body for user login.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the response body for successful login.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Login handles user login requests.
func (handler *AuthHandler) Login(gc *gin.Context) {
	// Parse request body
	var req LoginRequest
	if err := gc.ShouldBindJSON(&req); err != nil {
		gc.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call service layer to login user
	access, refresh, err := handler.service.Login(gc.Request.Context(), req.Email, req.Password)

	// Handle errors via middleware
	if err != nil {
		_ = gc.Error(err)
		return
	}

	// Write response
	gc.JSON(http.StatusOK, LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}
