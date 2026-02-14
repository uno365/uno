// Package token provides JWT token generation and verification.
package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims including user ID and standard registered claims.
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token operations.
type JWTManager struct {
	secret string
}

// NewJWTManager creates a new JWTManager with the given secret key.
func NewJWTManager(secret string) *JWTManager {
	return &JWTManager{secret: secret}
}

// Generate creates a new JWT token for the given user ID with the specified duration.
func (j *JWTManager) Generate(userID string, duration time.Duration) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "workspace-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secret))
}

// Verify validates a JWT token string and returns the claims if valid.
func (j *JWTManager) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		return []byte(j.secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, err
	}

	return claims, nil
}
