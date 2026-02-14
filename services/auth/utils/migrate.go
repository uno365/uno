package utils

import (
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"log/slog"
)

func RunMigrations(sourceURL string, databaseURL string) error {

	// Create a new migrate instance with the provided source and database URLs
	m, err := migrate.New(
		sourceURL,
		databaseURL,
	)
	if err != nil {
		slog.Default().Error("Failed to create migrate instance", "error", err)
		return err
	}

	// Ensure underlying connections are closed even if migrations succeed
	defer func() {
		if cerr, _ := m.Close(); cerr != nil {
			slog.Default().Warn("Failed to close migrate instance", "error", cerr)
		}
	}()

	// Apply all up migrations. ErrNoChange is not a failure, it just means we're already up to date.
	err = m.Up()

	if err != nil && err != migrate.ErrNoChange {
		slog.Default().Error("Failed to apply migrations", "error", err)
		return err
	}

	slog.Default().Info("Migrations applied successfully")
	return nil
}
