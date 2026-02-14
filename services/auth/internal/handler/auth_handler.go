// Package handler provides HTTP handlers for authentication endpoints.
package handler

import (
	"encoding/json"
	"net/http"

	"uno/services/auth/internal/middleware"
	"uno/services/auth/internal/service"
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
func (handler *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		http.Error(w, `{"error":"email and password are required"}`, http.StatusBadRequest)
		return
	}

	// Call service layer to register user
	access, refresh, err := handler.service.Register(r.Context(), req.Email, req.Password)

	// Handle errors via middleware
	if err != nil {
		middleware.SetError(w, r, err)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{
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
func (handler *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		http.Error(w, `{"error":"email and password are required"}`, http.StatusBadRequest)
		return
	}

	// Call service layer to login user
	access, refresh, err := handler.service.Login(r.Context(), req.Email, req.Password)

	// Handle errors via middleware
	if err != nil {
		middleware.SetError(w, r, err)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}
