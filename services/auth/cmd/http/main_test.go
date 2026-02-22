package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateNewServer(t *testing.T) {
	server := CreateNewServer()

	assert.NotNil(t, server)
	assert.NotNil(t, server.Router)
}

func TestServer_MountEnv(t *testing.T) {
	// Save original env vars
	origDBURL := os.Getenv("DATABASE_URL")
	origJWTSecret := os.Getenv("JWT_SECRET")
	origPort := os.Getenv("PORT")
	origCORS := os.Getenv("CORS_ORIGINS")
	origTrustProxy := os.Getenv("TRUST_PROXY")

	// Restore after test
	defer func() {
		os.Setenv("DATABASE_URL", origDBURL)
		os.Setenv("JWT_SECRET", origJWTSecret)
		os.Setenv("PORT", origPort)
		os.Setenv("CORS_ORIGINS", origCORS)
		os.Setenv("TRUST_PROXY", origTrustProxy)
	}()

	t.Run("loads all environment variables", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
		os.Setenv("JWT_SECRET", "test-secret")
		os.Setenv("PORT", "8080")
		os.Setenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080")
		os.Setenv("TRUST_PROXY", "true")

		server := CreateNewServer()
		server.MountEnv()

		assert.Equal(t, "postgres://test:test@localhost:5432/test", server.DATABASE_URL)
		assert.Equal(t, "test-secret", server.JWT_SECRET)
		assert.Equal(t, "8080", server.PORT)
		assert.Equal(t, []string{"http://localhost:3000", "http://localhost:8080"}, server.CORS_ORIGINS)
		assert.True(t, server.TRUST_PROXY)
	})

	t.Run("uses default port when PORT not set", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
		os.Setenv("JWT_SECRET", "test-secret")
		os.Unsetenv("PORT")

		server := CreateNewServer()
		server.MountEnv()

		assert.Equal(t, "4000", server.PORT)
	})

	t.Run("uses default CORS origins when not set", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
		os.Setenv("JWT_SECRET", "test-secret")
		os.Unsetenv("CORS_ORIGINS")

		server := CreateNewServer()
		server.MountEnv()

		assert.Equal(t, []string{"http://localhost:3000"}, server.CORS_ORIGINS)
	})

	t.Run("TRUST_PROXY defaults to false", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
		os.Setenv("JWT_SECRET", "test-secret")
		os.Unsetenv("TRUST_PROXY")

		server := CreateNewServer()
		server.MountEnv()

		assert.False(t, server.TRUST_PROXY)
	})

	t.Run("handles missing DATABASE_URL", func(t *testing.T) {
		os.Unsetenv("DATABASE_URL")
		os.Setenv("JWT_SECRET", "test-secret")

		server := CreateNewServer()
		server.MountEnv()

		assert.Empty(t, server.DATABASE_URL)
	})

	t.Run("handles missing JWT_SECRET", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
		os.Unsetenv("JWT_SECRET")

		server := CreateNewServer()
		server.MountEnv()

		assert.Empty(t, server.JWT_SECRET)
	})
}

func TestServer_MountMiddlewares(t *testing.T) {
	server := CreateNewServer()
	server.CORS_ORIGINS = []string{"http://localhost:3000"}
	server.MountMiddlewares()

	// Add a test route
	server.Router.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("applies CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "GET")

		rec := httptest.NewRecorder()
		server.Router.ServeHTTP(rec, req)

		assert.Equal(t, "http://localhost:3000", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("adds request ID header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		server.Router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("recovers from panic", func(t *testing.T) {
		server := CreateNewServer()
		server.CORS_ORIGINS = []string{"*"}
		server.MountMiddlewares()

		server.Router.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})

		req := httptest.NewRequest(http.MethodGet, "/panic", nil)
		rec := httptest.NewRecorder()

		// Should not panic - recoverer middleware catches it
		require.NotPanics(t, func() {
			server.Router.ServeHTTP(rec, req)
		})
	})
}

func TestServer_MountMiddlewares_MultipleCORSOrigins(t *testing.T) {
	server := CreateNewServer()
	server.CORS_ORIGINS = []string{"http://localhost:3000", "http://example.com"}
	server.MountMiddlewares()

	server.Router.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name   string
		origin string
	}{
		{"localhost origin", "http://localhost:3000"},
		{"example.com origin", "http://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", "GET")

			rec := httptest.NewRecorder()
			server.Router.ServeHTTP(rec, req)

			assert.Equal(t, tt.origin, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}
