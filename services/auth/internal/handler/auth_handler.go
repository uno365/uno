// Package handler provides HTTP handlers for authentication endpoints.
package handler

import (
	"encoding/json"
	"net/http"

	"uno/services/auth/internal/domain"
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

// Register handles user registration requests.
func (handler *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req domain.RegisterRequest
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
	json.NewEncoder(w).Encode(domain.RegisterResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}

// ================ Login ================

// Login handles user login requests.
func (handler *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req domain.LoginRequest
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
	json.NewEncoder(w).Encode(domain.LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}
