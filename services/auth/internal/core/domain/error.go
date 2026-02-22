// Package domain defines the core business entities and errors for the auth service.
package domain

import "errors"

// Domain errors for authentication operations.
var (
	// ErrInvalidCredentials is returned when login credentials are incorrect.
	ErrInvalidCredentials = errors.New("Invalid email or password")
	// ErrEmailExists is returned when attempting to register with an existing email.
	ErrEmailExists = errors.New("Email already registered")
	// ErrUserNotFound is returned when a user cannot be found.
	ErrUserNotFound = errors.New("User not found")
	// ErrInvalidToken is returned when a token is invalid or expired.
	ErrInvalidToken = errors.New("Invalid or expired token")
	// ErrSessionNotFound is returned when a session cannot be found.
	ErrSessionNotFound = errors.New("Session not found")
	// ErrSessionRevoked is returned when attempting to use a revoked session.
	ErrSessionRevoked = errors.New("Session has been revoked")
	// ErrTokenReuse is returned when refresh token reuse is detected.
	ErrTokenReuse = errors.New("Refresh token reuse detected")
)
