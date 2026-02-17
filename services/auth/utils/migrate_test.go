package utils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// createTestPostgresContainer creates a postgres container for testing migrations
func createTestPostgresContainer(ctx context.Context) (*postgres.PostgresContainer, string, error) {
	pgContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("migrate_test_db"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.BasicWaitStrategies(),
		postgres.WithSQLDriver("pgx"),
	)
	if err != nil {
		return nil, "", err
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx)
		return nil, "", err
	}

	return pgContainer, connStr, nil
}

func TestRunMigrationsInvalidDB(t *testing.T) {
	// invalid/unreachable database URL should result in error
	err := RunMigrations("file://migrations", "postgres://user:pass@localhost:5432/doesnotexist?sslmode=disable")
	assert.Error(t, err)
}

func TestRunMigrationsSuccess(t *testing.T) {
	ctx := context.Background()

	// Create postgres container
	container, connStr, err := createTestPostgresContainer(ctx)
	require.NoError(t, err, "failed to create postgres container")
	defer container.Terminate(ctx)

	// Create a temporary directory for migrations
	tempDir, err := os.MkdirTemp("", "migrations")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// Create a simple up migration
	upSQL := `CREATE TABLE test_table (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL
	);`
	err = os.WriteFile(filepath.Join(tempDir, "000001_create_test_table.up.sql"), []byte(upSQL), 0600)
	require.NoError(t, err, "failed to write up migration")

	// Create corresponding down migration
	downSQL := `DROP TABLE IF EXISTS test_table;`
	err = os.WriteFile(filepath.Join(tempDir, "000001_create_test_table.down.sql"), []byte(downSQL), 0600)
	require.NoError(t, err, "failed to write down migration")

	// Run migrations
	err = RunMigrations("file://"+tempDir, connStr)
	require.NoError(t, err, "RunMigrations should succeed")

	// Verify migration was applied by checking if table exists
	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err, "failed to create pool")
	defer pool.Close()

	// Check that the table exists by querying it
	var tableName string
	err = pool.QueryRow(ctx, "SELECT table_name FROM information_schema.tables WHERE table_name = 'test_table'").Scan(&tableName)
	require.NoError(t, err, "test_table should exist after migration")
	assert.Equal(t, "test_table", tableName)
}

func TestRunMigrationsNoChange(t *testing.T) {
	ctx := context.Background()

	// Create postgres container
	container, connStr, err := createTestPostgresContainer(ctx)
	require.NoError(t, err, "failed to create postgres container")
	defer container.Terminate(ctx)

	// Create a temporary directory for migrations
	tempDir, err := os.MkdirTemp("", "migrations")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// Create a simple migration
	upSQL := `CREATE TABLE another_table (id SERIAL PRIMARY KEY);`
	err = os.WriteFile(filepath.Join(tempDir, "000001_create_another_table.up.sql"), []byte(upSQL), 0600)
	require.NoError(t, err)

	downSQL := `DROP TABLE IF EXISTS another_table;`
	err = os.WriteFile(filepath.Join(tempDir, "000001_create_another_table.down.sql"), []byte(downSQL), 0600)
	require.NoError(t, err)

	// Run migrations first time
	err = RunMigrations("file://"+tempDir, connStr)
	require.NoError(t, err, "first migration should succeed")

	// Run migrations again - should return no error (ErrNoChange is handled)
	err = RunMigrations("file://"+tempDir, connStr)
	require.NoError(t, err, "second migration should succeed with no change")
}
