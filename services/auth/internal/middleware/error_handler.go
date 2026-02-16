// Package middleware provides HTTP middleware components for the auth service.
package middleware

import (
	"encoding/json"
	"errors"
	"net/http"

	"uno/services/auth/internal/domain"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// errorResponseWriter wraps http.ResponseWriter to track errors and written state
type errorResponseWriter struct {
	http.ResponseWriter
	err     error
	written bool
}

// WriteHeader captures the written state
func (w *errorResponseWriter) WriteHeader(code int) {
	w.written = true
	w.ResponseWriter.WriteHeader(code)
}

// Write captures the written state
func (w *errorResponseWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

// SetError stores an error to be handled by the middleware
func SetError(w http.ResponseWriter, _ *http.Request, err error) {
	if ew, ok := w.(*errorResponseWriter); ok {
		ew.err = err
	}
}

// ErrorHandler is a middleware that handles errors set via SetError
func ErrorHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the response writer
		ew := &errorResponseWriter{ResponseWriter: w}

		// Call the next handler
		next.ServeHTTP(ew, r)

		// Check if there's an error to handle
		if ew.err == nil {
			return
		}

		// Map domain errors to HTTP status codes
		status, response := mapError(ew.err)

		// Only write response if not already written
		if !ew.written {
			ew.ResponseWriter.Header().Set("Content-Type", "application/json")
			ew.ResponseWriter.WriteHeader(status)
			json.NewEncoder(ew.ResponseWriter).Encode(response)
		}
	})
}

// mapError maps domain errors to HTTP status codes and responses
func mapError(err error) (int, ErrorResponse) {
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		return http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: domain.ErrInvalidCredentials.Error(),
		}
	case errors.Is(err, domain.ErrInvalidToken):
		return http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: domain.ErrInvalidToken.Error(),
		}
	case errors.Is(err, domain.ErrEmailExists):
		return http.StatusConflict, ErrorResponse{
			Error:   "conflict",
			Message: domain.ErrEmailExists.Error(),
		}
	case errors.Is(err, domain.ErrUserNotFound):
		return http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: domain.ErrUserNotFound.Error(),
		}
	default:
		return http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "An unexpected error occurred",
		}
	}
}
