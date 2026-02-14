package utils

import (
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"testing"
)

func TestRunMigrationsInvalidDB(t *testing.T) {
	// invalid/unreachable database URL should result in error
	err := RunMigrations("file://migrations", "postgres://user:pass@localhost:5432/doesnotexist?sslmode=disable")
	if err == nil {
		t.Fatalf("expected error for invalid DB URL")
	}
}
