// Package utils provides utility functions for the auth service.
package postgres

import (
	"context"
	"embed"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
)

// migrationsFS is a filesystem that embeds the migrations folder

//go:embed migrations/*.sql
var migrationsFS embed.FS

type DB struct {
	*pgxpool.Pool
	url string
}

// NewDB creates a new database connection pool with the given URL and returns a DB instance.
func NewDB(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		slog.Default().Error("Failed to create database connection pool", "error", err)
		return nil, err
	}

	return &DB{Pool: pool, url: url}, nil
}

// Migrate applies all pending database migrations from the source URL to the database.
func (db *DB) Migrate() error {
	driver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return err
	}

	migrations, err := migrate.NewWithSourceInstance("iofs", driver, db.url)
	if err != nil {
		return err
	}

	err = migrations.Up()
	if err != nil && err != migrate.ErrNoChange {
		return err
	}

	return nil
}

// Close terminates the database connection pool.
func (db *DB) Close() {
	db.Pool.Close()
}
