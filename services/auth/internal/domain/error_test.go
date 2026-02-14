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
		{"invalid_credentials", ErrInvalidCredentials, "invalid credentials"},
		{"email_exists", ErrEmailExists, "email already exists"},
		{"user_not_found", ErrUserNotFound, "user not found"},
	}

	for _, errorCase := range errorCases {
		t.Run(errorCase.errorName, func(t *testing.T) {
			require.NotNil(t, errorCase.errorType)
			assert.Equal(t, errorCase.expectedErrorMessage, errorCase.errorType.Error())
		})
	}
}
