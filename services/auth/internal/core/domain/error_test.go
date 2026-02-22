package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainErrors(t *testing.T) {
	// test that all domain errors are non-nil and have expected messages
	errorCases := []struct {
		errorName            string
		errorType            error
		expectedErrorMessage string
	}{
		{"invalid_credentials", ErrInvalidCredentials, "Invalid email or password"},
		{"email_exists", ErrEmailExists, "Email already registered"},
		{"user_not_found", ErrUserNotFound, "User not found"},
	}

	for _, errorCase := range errorCases {
		t.Run(errorCase.errorName, func(t *testing.T) {
			require.NotNil(t, errorCase.errorType)
			assert.Equal(t, errorCase.expectedErrorMessage, errorCase.errorType.Error())
		})
	}
}
