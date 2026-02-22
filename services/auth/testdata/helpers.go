package testdata

import (
	"context"

	"uno/services/auth/internal/adapter/db/postgres"
)

// TestDB holds the postgres container and database connection pool for testing
type TestDB struct {
	PostgresContainer *PostgresContainer
	DB                *postgres.DB
}

// SetupTestDB creates a postgres test container, runs migrations, and returns a database connection pool
func SetupTestDB(ctx context.Context) (*TestDB, error) {
	// Create postgres container
	pgContainer, err := CreatePostgresContainer(ctx)

	if err != nil {
		return nil, err
	}

	db, err := postgres.NewDB(ctx, pgContainer.ConnectionString)

	if err != nil {
		pgContainer.Container.Terminate(ctx)
		return nil, err
	}

	if err := db.Migrate(); err != nil {
		pgContainer.Container.Terminate(ctx)
		return nil, err
	}

	return &TestDB{
		PostgresContainer: pgContainer,
		DB:                db,
	}, nil
}

// Teardown closes the database connection and terminates the container
func (t *TestDB) Teardown(ctx context.Context) error {
	if t.DB != nil {
		t.DB.Close()
	}
	if t.PostgresContainer != nil {
		return t.PostgresContainer.Container.Terminate(ctx)
	}
	return nil
}
