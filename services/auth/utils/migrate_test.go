package utils

import (
	"testing"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/assert"
)

func TestRunMigrationsInvalidDB(t *testing.T) {
	// invalid/unreachable database URL should result in error
	err := RunMigrations("file://migrations", "postgres://user:pass@localhost:5432/doesnotexist?sslmode=disable")
	assert.Error(t, err)
}
