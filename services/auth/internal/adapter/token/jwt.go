// Package token provides JWT token generation and verification.
package token

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
	"uno/services/auth/internal/core/domain"
)

// Claims represents the JWT claims including user ID and standard registered claims.
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// JWT handles JWT token operations.
type JWT struct {
	secret string
}

// NewJWT creates a new JWT with the given secret key.
func NewJWT(secret string) *JWT {
	return &JWT{secret: secret}
}

// Generate creates a new JWT token for the given user ID with the specified duration.
func (j *JWT) Generate(userID string, duration time.Duration) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "uno-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secret))
}

// Verify validates a JWT token string and returns the claims if valid.
func (j *JWT) Verify(tokenStr string) (*domain.TokenPayload, error) {
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

	return &domain.TokenPayload{UserID: claims.UserID}, nil
}
