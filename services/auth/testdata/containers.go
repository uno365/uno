// Package testdata provides test utilities including database containers and helpers.
package testdata

import (
	"context"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// PostgresContainer wraps a postgres test container with its connection string.
type PostgresContainer struct {
	Container        *postgres.PostgresContainer
	ConnectionString string
}

// Database configuration constants for test containers.
const (
	dbName     = "auth_db_test"
	dbUser     = "postgres"
	dbPassword = "postgres"
)

// CreatePostgresContainer creates and starts a new PostgreSQL test container.
func CreatePostgresContainer(ctx context.Context) (*PostgresContainer, error) {

	pgContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		postgres.BasicWaitStrategies(),
		postgres.WithSQLDriver("pgx"),
	)

	if err != nil {
		return nil, err
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")

	if err != nil {
		return nil, err
	}

	return &PostgresContainer{
		Container:        pgContainer,
		ConnectionString: connStr,
	}, nil
}
