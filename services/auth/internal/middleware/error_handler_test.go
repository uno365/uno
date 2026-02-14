package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"uno/services/auth/internal/domain"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestErrorHandler(t *testing.T) {

	t.Run("no errors passes through", func(t *testing.T) {
		// Setup router with middleware
		router := gin.New()
		router.Use(ErrorHandler())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		// Make request
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Verify response passes through unchanged
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "ok")
	})

	t.Run("ErrInvalidCredentials returns 401", func(t *testing.T) {
		// Setup router with middleware
		router := gin.New()
		router.Use(ErrorHandler())
		router.GET("/test", func(c *gin.Context) {
			_ = c.Error(domain.ErrInvalidCredentials)
		})

		// Make request
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Verify 401 status code
		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		// Verify response body
		var resp ErrorResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "unauthorized", resp.Error)
		assert.Equal(t, "Invalid email or password", resp.Message)
	})

	t.Run("ErrEmailExists returns 409", func(t *testing.T) {
		// Setup router with middleware
		router := gin.New()
		router.Use(ErrorHandler())
		router.GET("/test", func(c *gin.Context) {
			_ = c.Error(domain.ErrEmailExists)
		})

		// Make request
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Verify 409 status code
		assert.Equal(t, http.StatusConflict, rr.Code)

		// Verify response body
		var resp ErrorResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "conflict", resp.Error)
		assert.Equal(t, "Email already registered", resp.Message)
	})

	t.Run("ErrUserNotFound returns 404", func(t *testing.T) {
		// Setup router with middleware
		router := gin.New()
		router.Use(ErrorHandler())
		router.GET("/test", func(c *gin.Context) {
			_ = c.Error(domain.ErrUserNotFound)
		})

		// Make request
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Verify 404 status code
		assert.Equal(t, http.StatusNotFound, rr.Code)

		// Verify response body
		var resp ErrorResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "not_found", resp.Error)
		assert.Equal(t, "User not found", resp.Message)
	})

	t.Run("unknown error returns 500", func(t *testing.T) {
		// Setup router with middleware
		router := gin.New()
		router.Use(ErrorHandler())
		router.GET("/test", func(c *gin.Context) {
			_ = c.Error(errors.New("some unexpected error"))
		})

		// Make request
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Verify 500 status code
		assert.Equal(t, http.StatusInternalServerError, rr.Code)

		// Verify response body
		var resp ErrorResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "internal_error", resp.Error)
		assert.Equal(t, "An unexpected error occurred", resp.Message)
	})

	t.Run("does not overwrite already written response", func(t *testing.T) {
		// Setup router with middleware
		router := gin.New()
		router.Use(ErrorHandler())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusBadRequest, gin.H{"custom": "error"})
			_ = c.Error(domain.ErrInvalidCredentials)
		})

		// Make request
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Verify original response is preserved
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "custom")
	})

	t.Run("wrapped domain error is handled correctly", func(t *testing.T) {
		// Setup router with middleware
		router := gin.New()
		router.Use(ErrorHandler())
		router.GET("/test", func(c *gin.Context) {
			wrappedErr := errors.Join(errors.New("context"), domain.ErrEmailExists)
			_ = c.Error(wrappedErr)
		})

		// Make request
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Verify wrapped error is unwrapped correctly
		assert.Equal(t, http.StatusConflict, rr.Code)

		// Verify response body
		var resp ErrorResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "conflict", resp.Error)
		assert.Equal(t, "Email already registered", resp.Message)
	})
}
