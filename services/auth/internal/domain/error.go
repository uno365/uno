// Package domain defines the core business entities and errors for the auth service.
package domain

import "errors"

// Domain errors for authentication operations.
var (
	// ErrInvalidCredentials is returned when login credentials are incorrect.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrEmailExists is returned when attempting to register with an existing email.
	ErrEmailExists = errors.New("email already exists")
	// ErrUserNotFound is returned when a user cannot be found.
	ErrUserNotFound = errors.New("user not found")
)
