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
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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

	// Setup router with real DB connection
	router := SetupAuthRouter(db.Pool, "test-secret")

	// Start test server
	server := httptest.NewServer(router)

	// Define cleanup function to close server and teardown DB
	cleanup := func() {
		server.Close()
		db.Teardown(ctx)
	}

	return server.URL, cleanup
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
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body authResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.NotEmpty(t, body.AccessToken)
		assert.NotEmpty(t, body.RefreshToken)
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
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

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
		require.Equal(t, http.StatusOK, regResp.StatusCode)

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
		assert.NotEmpty(t, body.RefreshToken)
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
}
