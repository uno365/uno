package handler

import (
	"encoding/json"
	"net/http"
	"uno/services/auth/internal/service"
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
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (handler *AuthHandler) Register(responseWriter http.ResponseWriter, request *http.Request) {

	// Parse request body
	var req RegisterRequest
	json.NewDecoder(request.Body).Decode(&req)

	// Call service layer to register user
	access, refresh, err := handler.service.Register(request.Context(), req.Email, req.Password)

	// Handle errors
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusBadRequest)
		return
	}

	// Write response
	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(RegisterResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}

// ================ Login ================

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (handler *AuthHandler) Login(responseWriter http.ResponseWriter, request *http.Request) {

	// Parse request body
	var req LoginRequest
	json.NewDecoder(request.Body).Decode(&req)

	// Call service layer to login user
	access, refresh, err := handler.service.Login(request.Context(), req.Email, req.Password)

	// Handle errors
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusUnauthorized)
		return
	}

	// Write response
	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}
