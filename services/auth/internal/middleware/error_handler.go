package middleware

import (
	"errors"
	"net/http"

	"uno/services/auth/internal/domain"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// ErrorHandler is a middleware that handles errors added to the Gin context
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are any errors
		if len(c.Errors) == 0 {
			return
		}

		// Get the last error
		err := c.Errors.Last().Err

		// Map domain errors to HTTP status codes
		status, response := mapError(err)

		// Only write response if not already written
		if !c.Writer.Written() {
			c.JSON(status, response)
		}
	}
}

// mapError maps domain errors to HTTP status codes and responses
func mapError(err error) (int, ErrorResponse) {
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		return http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid email or password",
		}
	case errors.Is(err, domain.ErrEmailExists):
		return http.StatusConflict, ErrorResponse{
			Error:   "conflict",
			Message: "Email already registered",
		}
	case errors.Is(err, domain.ErrUserNotFound):
		return http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: "User not found",
		}
	default:
		return http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "An unexpected error occurred",
		}
	}
}
