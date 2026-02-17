package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"uno/services/auth/utils/testdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type authResponse struct {
	AccessToken string `json:"access_token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// setupTest creates a test DB, starts a test server, and returns the server URL along with a cleanup function
func setupTest(t *testing.T) (string, func()) {
	t.Helper()
	ctx := context.Background()

	// Setup test DB
	db, err := testdata.SetupTestDB(ctx)
	require.NoError(t, err, "failed to setup test DB")

	// Setup server with real DB connection
	s := CreateNewServer()
	s.DB = db.Pool
	s.JWT_SECRET = "test-secret"
	s.MountHandlers()

	// Start test server
	testServer := httptest.NewServer(s.Router)

	// Define cleanup function to close server and teardown DB
	cleanup := func() {
		testServer.Close()
		db.Teardown(ctx)
	}

	return testServer.URL, cleanup
}

// getRefreshTokenCookie extracts the refresh_token cookie from the response
func getRefreshTokenCookie(resp *http.Response) string {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "refresh_token" {
			return cookie.Value
		}
	}
	return ""
}

// Integration test for the server wiring using a real Postgres DB.
func TestServerIntegration(t *testing.T) {

	t.Run("Register endpoint success", func(t *testing.T) {

		// Setup test server and DB
		serverURL, cleanup := setupTest(t)
		defer cleanup()

		// Make HTTP request to register endpoint
		reqBody := map[string]string{"email": "alice@example.com", "password": "pass"}
		reqBodyJSON, _ := json.Marshal(reqBody)
		resp, err := http.Post(serverURL+"/register", "application/json", bytes.NewReader(reqBodyJSON))
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		var body authResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.NotEmpty(t, body.AccessToken)

		// Verify refresh token is in cookie
		refreshCookie := getRefreshTokenCookie(resp)
		assert.NotEmpty(t, refreshCookie, "refresh_token cookie should be set")
	})

	t.Run("Register duplicate email", func(t *testing.T) {

		// Setup test server and DB
		serverURL, cleanup := setupTest(t)
		defer cleanup()

		// pre-create via HTTP
		reqBody := map[string]string{"email": "dup@example.com", "password": "pass"}
		reqBodyJSON, _ := json.Marshal(reqBody)
		_, _ = http.Post(serverURL+"/register", "application/json", bytes.NewReader(reqBodyJSON))

		// second attempt should fail
		resp, err := http.Post(serverURL+"/register", "application/json", bytes.NewReader(reqBodyJSON))
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		require.Equal(t, http.StatusConflict, resp.StatusCode)

		var body errorResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.NotEmpty(t, body.Error)
	})

	t.Run("Login endpoint success", func(t *testing.T) {

		// Setup test server and DB
		serverURL, cleanup := setupTest(t)
		defer cleanup()

		// create a user via HTTP and ensure success
		reqBody := map[string]string{"email": "bob@example.com", "password": "pass"}
		reqBodyJSON, _ := json.Marshal(reqBody)
		regResp, err := http.Post(serverURL+"/register", "application/json", bytes.NewReader(reqBodyJSON))
		require.NoError(t, err)
		defer regResp.Body.Close()
		require.Equal(t, http.StatusCreated, regResp.StatusCode)

		// Make HTTP request to login endpoint
		resp, err := http.Post(serverURL+"/login", "application/json", bytes.NewReader(reqBodyJSON))
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body authResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.NotEmpty(t, body.AccessToken)

		// Verify refresh token is in cookie
		refreshCookie := getRefreshTokenCookie(resp)
		assert.NotEmpty(t, refreshCookie, "refresh_token cookie should be set")
	})

	t.Run("Login unauthorized", func(t *testing.T) {

		// Setup test server and DB
		serverURL, cleanup := setupTest(t)
		defer cleanup()

		reqBody := map[string]string{"email": "missing@example.com", "password": "pass"}
		reqBodyJSON, _ := json.Marshal(reqBody)
		resp, err := http.Post(serverURL+"/login", "application/json", bytes.NewReader(reqBodyJSON))
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var body errorResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.NotEmpty(t, body.Error)
	})

	t.Run("Refresh endpoint success", func(t *testing.T) {

		// Setup test server and DB
		serverURL, cleanup := setupTest(t)
		defer cleanup()

		// Register a user
		reqBody := map[string]string{"email": "refresh@example.com", "password": "pass"}
		reqBodyJSON, _ := json.Marshal(reqBody)
		regResp, err := http.Post(serverURL+"/register", "application/json", bytes.NewReader(reqBodyJSON))
		require.NoError(t, err)
		defer regResp.Body.Close()
		require.Equal(t, http.StatusCreated, regResp.StatusCode)

		// Get refresh token from cookie
		refreshToken := getRefreshTokenCookie(regResp)
		require.NotEmpty(t, refreshToken)

		// Make refresh request with cookie
		client := &http.Client{}
		req, _ := http.NewRequest(http.MethodPost, serverURL+"/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body authResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.NotEmpty(t, body.AccessToken)

		// Verify new refresh token is in cookie (rotation)
		newRefreshCookie := getRefreshTokenCookie(resp)
		assert.NotEmpty(t, newRefreshCookie, "new refresh_token cookie should be set")
		assert.NotEqual(t, refreshToken, newRefreshCookie, "refresh token should be rotated")
	})

	t.Run("Logout endpoint success", func(t *testing.T) {

		// Setup test server and DB
		serverURL, cleanup := setupTest(t)
		defer cleanup()

		// Register a user
		reqBody := map[string]string{"email": "logout@example.com", "password": "pass"}
		reqBodyJSON, _ := json.Marshal(reqBody)
		regResp, err := http.Post(serverURL+"/register", "application/json", bytes.NewReader(reqBodyJSON))
		require.NoError(t, err)
		defer regResp.Body.Close()
		require.Equal(t, http.StatusCreated, regResp.StatusCode)

		// Get refresh token from cookie
		refreshToken := getRefreshTokenCookie(regResp)
		require.NotEmpty(t, refreshToken)

		// Logout
		client := &http.Client{}
		req, _ := http.NewRequest(http.MethodPost, serverURL+"/logout", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify cookie is cleared
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "refresh_token" {
				assert.True(t, cookie.MaxAge < 0, "cookie should be cleared")
			}
		}
	})
}
