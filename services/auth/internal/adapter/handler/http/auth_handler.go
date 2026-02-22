// Package http provides HTTP handlers for authentication endpoints.
package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"uno/services/auth/internal/adapter/handler/http/middleware"
	"uno/services/auth/internal/core/domain"
	"uno/services/auth/internal/core/port"
)

const (
	refreshTokenCookieName = "refresh_token"
	refreshTokenMaxAge     = 7 * 24 * 60 * 60 // 7 days in seconds
)

// ================ Type and Constructor ================

// AuthHandler handles HTTP requests for authentication operations.
type AuthHandler struct {
	service           port.AuthService
	trustProxyHeaders bool
}

// NewAuthHandler creates a new AuthHandler with the given AuthService.
// Set trustProxyHeaders to true only when running behind a properly configured
// reverse proxy that overwrites X-Forwarded-For and X-Real-IP headers.
func NewAuthHandler(s port.AuthService, trustProxyHeaders bool) *AuthHandler {
	return &AuthHandler{
		service:           s,
		trustProxyHeaders: trustProxyHeaders,
	}
}

// ================ Helper Functions ================

// isSecureRequest determines if the request is over a secure connection.
// Returns true for HTTPS connections or when behind a trusted proxy with X-Forwarded-Proto: https.
// Returns false for localhost/127.0.0.1 to support local development over HTTP.
func (handler *AuthHandler) isSecureRequest(r *http.Request) bool {
	// Only trust X-Forwarded-Proto when proxy headers are explicitly trusted
	if handler.trustProxyHeaders && r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}

	// Check if direct TLS connection
	if r.TLS != nil {
		return true
	}

	// Allow insecure cookies for localhost development
	host := r.Host
	if host == "localhost" || host == "127.0.0.1" ||
		strings.HasPrefix(host, "localhost:") ||
		strings.HasPrefix(host, "127.0.0.1:") {
		return false
	}

	// Default to secure for production
	return true
}

// setRefreshTokenCookie sets the refresh token as an HTTP-only secure cookie.
func (handler *AuthHandler) setRefreshTokenCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   refreshTokenMaxAge,
		HttpOnly: true,
		Secure:   handler.isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearRefreshTokenCookie removes the refresh token cookie.
func (handler *AuthHandler) clearRefreshTokenCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   handler.isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
	})
}

// getClientInfo extracts user agent and IP address from the request.
// When trustProxyHeaders is false, only r.RemoteAddr is used for the IP address.
// When trustProxyHeaders is true, X-Forwarded-For and X-Real-IP headers are trusted.
// Only enable trustProxyHeaders when running behind a properly configured reverse proxy.
func (handler *AuthHandler) getClientInfo(r *http.Request) (userAgent, ipAddress string) {
	userAgent = r.UserAgent()

	// Only trust proxy headers if explicitly configured
	if handler.trustProxyHeaders {
		// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
		// Extract only the first (original client) IP
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ipAddress = strings.TrimSpace(strings.Split(xff, ",")[0])
		}
		if ipAddress == "" {
			ipAddress = r.Header.Get("X-Real-IP")
		}
	}

	// Fall back to RemoteAddr
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}

	return userAgent, ipAddress
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

	// Get client info
	userAgent, ipAddress := handler.getClientInfo(r)

	// Call service layer to register user
	access, refresh, err := handler.service.Register(r.Context(), req.Email, req.Password, userAgent, ipAddress)

	// Handle errors via middleware
	if err != nil {
		middleware.SetError(w, r, err)
		return
	}

	// Set refresh token cookie
	handler.setRefreshTokenCookie(w, r, refresh)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(domain.AuthResponse{
		AccessToken: access,
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

	// Get client info
	userAgent, ipAddress := handler.getClientInfo(r)

	// Call service layer to login user
	access, refresh, err := handler.service.Login(r.Context(), req.Email, req.Password, userAgent, ipAddress)

	// Handle errors via middleware
	if err != nil {
		middleware.SetError(w, r, err)
		return
	}

	// Set refresh token cookie
	handler.setRefreshTokenCookie(w, r, refresh)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(domain.AuthResponse{
		AccessToken: access,
	})
}

// ================ Refresh Token ================

// Refresh handles token refresh requests.
func (handler *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Read refresh token from cookie
	cookie, err := r.Cookie(refreshTokenCookieName)

	if err != nil || cookie.Value == "" {
		http.Error(w, `{"error":"refresh token is required"}`, http.StatusBadRequest)
		return
	}

	// Get client info
	userAgent, ipAddress := handler.getClientInfo(r)

	// Call service layer to refresh tokens
	access, refresh, err := handler.service.Refresh(r.Context(), cookie.Value, userAgent, ipAddress)

	// Handle errors via middleware
	if err != nil {
		// Clear the invalid cookie
		handler.clearRefreshTokenCookie(w, r)
		middleware.SetError(w, r, err)
		return
	}

	// Set new refresh token cookie (rotation)
	handler.setRefreshTokenCookie(w, r, refresh)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(domain.AuthResponse{
		AccessToken: access,
	})
}

// ================ Logout ================

// Logout handles user logout requests by revoking the session and clearing the cookie.
func (handler *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Read refresh token from cookie
	cookie, err := r.Cookie(refreshTokenCookieName)
	refreshToken := ""
	if err == nil && cookie.Value != "" {
		refreshToken = cookie.Value
	}

	// Call service layer to logout (revoke session)
	if err := handler.service.Logout(r.Context(), refreshToken); err != nil {
		slog.Error("failed to revoke session during logout", "error", err)
	}

	// Clear the refresh token cookie
	handler.clearRefreshTokenCookie(w, r)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out successfully"})
}
