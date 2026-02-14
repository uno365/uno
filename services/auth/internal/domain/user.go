package domain

import "time"

// User represents a registered user in the system.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}
