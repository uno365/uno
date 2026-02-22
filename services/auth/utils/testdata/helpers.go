package testdata

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"uno/services/auth/internal/adapter/db/postgres"
	"uno/services/auth/utils"
)

// TestDB holds the postgres container and database connection pool for testing
type TestDB struct {
	Container *PostgresContainer
	DB        *postgres.DB
}

// SetupTestDB creates a postgres test container, runs migrations, and returns a database connection pool
func SetupTestDB(ctx context.Context) (*TestDB, error) {
	// Create postgres container
	container, err := CreatePostgresContainer(ctx)

	if err != nil {
		return nil, err
	}

	db, err := postgres.NewDB(ctx, container.ConnectionString)

	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}

	db.Migrate()

	return &TestDB{
		Container: container,
		DB:        db,
	}, nil
}

// Teardown closes the database connection and terminates the container
func (t *TestDB) Teardown(ctx context.Context) error {
	if t.DB != nil {
		t.DB.Close()
	}
	if t.Container != nil {
		return t.Container.Terminate(ctx)
	}
	return nil
}
