package handler

import (
	"net/http"

	"uno/services/auth/internal/service"

	"github.com/gin-gonic/gin"
)

// ================ Type and Constructor ================

type AuthHandler struct {
	service *service.AuthService
}

func NewAuthHandler(s *service.AuthService) *AuthHandler {
	return &AuthHandler{service: s}
}

// ================ Registration ================

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RegisterResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (handler *AuthHandler) Register(gc *gin.Context) {
	// Parse request body
	var req RegisterRequest
	if err := gc.ShouldBindJSON(&req); err != nil {
		gc.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call service layer to register user
	access, refresh, err := handler.service.Register(gc.Request.Context(), req.Email, req.Password)

	// Handle errors
	if err != nil {
		gc.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Write response
	gc.JSON(http.StatusOK, RegisterResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}

// ================ Login ================

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (handler *AuthHandler) Login(gc *gin.Context) {
	// Parse request body
	var req LoginRequest
	if err := gc.ShouldBindJSON(&req); err != nil {
		gc.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call service layer to login user
	access, refresh, err := handler.service.Login(gc.Request.Context(), req.Email, req.Password)

	// Handle errors
	if err != nil {
		gc.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Write response
	gc.JSON(http.StatusOK, LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}
