package testdata

import (
	"context"
	"fmt"
	"os"
	"strings"

	"uno/services/auth/utils"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDB holds the postgres container and database connection pool for testing
type TestDB struct {
	Container *PostgresContainer
	Pool      *pgxpool.Pool
}

// SetupTestDB creates a postgres test container, runs migrations, and returns a database connection pool
func SetupTestDB(ctx context.Context) (*TestDB, error) {
	// Create postgres container
	container, err := CreatePostgresContainer(ctx)
	if err != nil {
		return nil, err
	}

	// Run migrations
	migrationsPath, err := migrationsDir()
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}
	err = utils.RunMigrations("file://"+migrationsPath, container.ConnectionString)
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}

	// Create database connection pool
	pool, err := pgxpool.New(ctx, container.ConnectionString)
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}

	return &TestDB{
		Container: container,
		Pool:      pool,
	}, nil
}

// Teardown closes the database connection and terminates the container
func (t *TestDB) Teardown(ctx context.Context) error {
	if t.Pool != nil {
		t.Pool.Close()
	}
	if t.Container != nil {
		return t.Container.Terminate(ctx)
	}
	return nil
}

func migrationsDir() (string, error) {
	dir, err := os.Getwd()

	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	authIdx := strings.LastIndex(dir, "/auth")
	if authIdx == -1 {
		return "", fmt.Errorf("could not find /auth in working directory")
	}

	return dir[:authIdx+5] + "/migrations", nil
}
