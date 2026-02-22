package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"uno/services/auth/internal/core/domain"
)

func TestErrorHandler_NoError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"success": true`)
}

func TestErrorHandler_InvalidCredentials(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, domain.ErrInvalidCredentials)
	})

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", resp.Error)
	assert.Equal(t, domain.ErrInvalidCredentials.Error(), resp.Message)
}

func TestErrorHandler_InvalidToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, domain.ErrInvalidToken)
	})

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", resp.Error)
	assert.Equal(t, domain.ErrInvalidToken.Error(), resp.Message)
}

func TestErrorHandler_SessionRevoked(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, domain.ErrSessionRevoked)
	})

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", resp.Error)
	assert.Equal(t, domain.ErrSessionRevoked.Error(), resp.Message)
}

func TestErrorHandler_TokenReuse(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, domain.ErrTokenReuse)
	})

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", resp.Error)
	assert.Equal(t, domain.ErrTokenReuse.Error(), resp.Message)
}

func TestErrorHandler_EmailExists(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, domain.ErrEmailExists)
	})

	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "conflict", resp.Error)
	assert.Equal(t, domain.ErrEmailExists.Error(), resp.Message)
}

func TestErrorHandler_UserNotFound(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, domain.ErrUserNotFound)
	})

	req := httptest.NewRequest(http.MethodGet, "/user/123", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "not_found", resp.Error)
	assert.Equal(t, domain.ErrUserNotFound.Error(), resp.Message)
}

func TestErrorHandler_UnknownError(t *testing.T) {
	unknownErr := errors.New("some unexpected error")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, unknownErr)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "internal_error", resp.Error)
	assert.Equal(t, "An unexpected error occurred", resp.Message)
}

func TestErrorHandler_ResponseAlreadyWritten(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"already": "written"}`))
		SetError(w, r, domain.ErrInvalidCredentials)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"already": "written"`)
}

func TestErrorHandler_WriteHeaderMarksWritten(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		SetError(w, r, domain.ErrInvalidCredentials)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestSetError_WithNonWrappedWriter(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SetError(rr, req, domain.ErrInvalidCredentials)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestErrorHandler_ContentTypeIsJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, domain.ErrInvalidCredentials)
	})

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

func TestErrorHandler_WrappedErrors(t *testing.T) {
	wrappedErr := errors.Join(errors.New("context"), domain.ErrInvalidCredentials)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetError(w, r, wrappedErr)
	})

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rr := httptest.NewRecorder()

	ErrorHandler(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}
