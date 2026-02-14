package token

import (
	"testing"
	"time"
)

func TestJWTGenerateAndVerify(t *testing.T) {
	jwtManager := NewJWTManager("secret")
	tokenString, generateErr := jwtManager.Generate("user-123", time.Minute)
	if generateErr != nil {
		t.Fatalf("Generate error: %v", generateErr)
	}
	if tokenString == "" {
		t.Fatalf("expected non-empty token")
	}

	parsedClaims, verifyErr := jwtManager.Verify(tokenString)
	if verifyErr != nil {
		t.Fatalf("Verify error: %v", verifyErr)
	}
	if parsedClaims == nil || parsedClaims.UserID != "user-123" {
		t.Fatalf("unexpected claims: %+v", parsedClaims)
	}
	if parsedClaims.ExpiresAt == nil || time.Until(parsedClaims.ExpiresAt.Time) <= 0 {
		t.Fatalf("expected future expiry, got: %v", parsedClaims.ExpiresAt)
	}
}

func TestJWTVerifyInvalidSecret(t *testing.T) {
	firstManager := NewJWTManager("secret1")
	secondManager := NewJWTManager("secret2")
	tokenString, generateErr := firstManager.Generate("id", time.Minute)
	if generateErr != nil {
		t.Fatalf("Generate error: %v", generateErr)
	}
	if _, verifyErr := secondManager.Verify(tokenString); verifyErr == nil {
		t.Fatalf("expected error when verifying with wrong secret")
	}
}
