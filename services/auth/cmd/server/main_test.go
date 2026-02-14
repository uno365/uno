package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"uno/services/auth/utils/testutils/conncase"
)

// Integration test for the server wiring using a real Postgres DB.
func TestServerIntegration(t *testing.T) {
	cc := conncase.NewConnCase(t)

	t.Run("Register endpoint success", func(t *testing.T) {
		cc.ResetOnCleanup(t)

		reqBody := map[string]string{"email": "alice@example.com", "password": "pass"}
		b, _ := json.Marshal(reqBody)
		resp, err := http.Post(cc.URL()+"/register", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("Register duplicate email", func(t *testing.T) {
		cc.ResetOnCleanup(t)

		// pre-create via HTTP
		reqBody := map[string]string{"email": "dup@example.com", "password": "pass"}
		b, _ := json.Marshal(reqBody)
		_, _ = http.Post(cc.URL()+"/register", "application/json", bytes.NewReader(b))

		// second attempt should fail
		resp, err := http.Post(cc.URL()+"/register", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("Login endpoint success", func(t *testing.T) {
		cc.ResetOnCleanup(t)

		// create a user via HTTP and ensure success
		reqBody := map[string]string{"email": "bob@example.com", "password": "pass"}
		b, _ := json.Marshal(reqBody)
		regResp, regErr := http.Post(cc.URL()+"/register", "application/json", bytes.NewReader(b))
		if regErr != nil {
			t.Fatalf("register request error: %v", regErr)
		}
		defer regResp.Body.Close()
		if regResp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(regResp.Body)
			t.Fatalf("register status: got %d want %d; body: %s", regResp.StatusCode, http.StatusOK, string(bodyBytes))
		}

		resp, err := http.Post(cc.URL()+"/login", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("Login unauthorized", func(t *testing.T) {
		cc.ResetOnCleanup(t)

		reqBody := map[string]string{"email": "missing@example.com", "password": "pass"}
		b, _ := json.Marshal(reqBody)
		resp, err := http.Post(cc.URL()+"/login", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})
}
