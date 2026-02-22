package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var testConnString string
var testContainer *postgres.PostgresContainer

func TestMain(m *testing.M) {
	ctx := context.Background()

	var err error
	testContainer, err = postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("auth_db_test"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.BasicWaitStrategies(),
		postgres.WithSQLDriver("pgx"),
	)
	if err != nil {
		panic("failed to create postgres container: " + err.Error())
	}

	testConnString, err = testContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		panic("failed to get connection string: " + err.Error())
	}

	code := m.Run()

	testContainer.Terminate(ctx)
	os.Exit(code)
}

func TestNewDB(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, testConnString)

	require.NoError(t, err)
	assert.NotNil(t, db)
	assert.NotNil(t, db.Pool)

	err = db.Pool.Ping(ctx)
	assert.NoError(t, err)

	db.Close()
}

func TestNewDB_InvalidURL(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, "postgres://invalid:invalid@localhost:9999/invalid")
	if err != nil {
		// Connection failed immediately (expected)
		return
	}
	defer db.Close()

	// pgxpool lazily connects - ping should fail
	err = db.Pool.Ping(ctx)
	assert.Error(t, err)
}

func TestDB_Migrate(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, testConnString)
	require.NoError(t, err)
	defer db.Close()

	err = db.Migrate()

	require.NoError(t, err)

	// Verify tables were created by querying them
	var exists bool
	err = db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_name = 'users'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "users table should exist after migration")

	err = db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_name = 'sessions'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "sessions table should exist after migration")
}

func TestDB_Migrate_Idempotent(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, testConnString)
	require.NoError(t, err)
	defer db.Close()

	// Run migration twice - should not error
	err = db.Migrate()
	require.NoError(t, err)

	err = db.Migrate()
	require.NoError(t, err)
}

func TestDB_Close(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, testConnString)
	require.NoError(t, err)

	db.Close()

	// Pool should be closed - Ping should fail
	err = db.Pool.Ping(ctx)
	assert.Error(t, err)
}
