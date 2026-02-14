package domain

import "testing"

func TestDomainErrors(t *testing.T) {
	// test that all domain errors are non-nil and have expected messages
	errorCases := []struct {
		errorName            string
		errorType            error
		expectedErrorMessage string
	}{
		{"invalid_credentials", ErrInvalidCredentials, "invalid credentials"},
		{"email_exists", ErrEmailExists, "email already exists"},
		{"user_not_found", ErrUserNotFound, "user not found"},
	}

	for _, errorCase := range errorCases {
		// check non-nil
		if errorCase.errorType == nil {
			t.Fatalf("%s: expected non-nil error", errorCase.errorName)
		}
		// check error message
		if errorMessage := errorCase.errorType.Error(); errorMessage != errorCase.expectedErrorMessage {
			t.Fatalf("%s: got %q, want %q", errorCase.errorName, errorMessage, errorCase.expectedErrorMessage)
		}
	}
}
