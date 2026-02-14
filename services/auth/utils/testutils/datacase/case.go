package datacase

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"uno/services/auth/utils"
	"uno/services/auth/utils/testutils"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// DataCase encapsulates a Postgres test container, its DB URL, and a pgx pool.
// Use NewDataCase in each test to get a clean database with migrations applied.
type DataCase struct {
	ctx       context.Context
	container *testutils.PostgresContainer
	dbURL     string
	pool      *pgxpool.Pool
}

// NewDataCase starts a Postgres test container, runs migrations, snapshots the DB,
// and returns a ready pgx pool. It also registers cleanup to restore the snapshot
// after the test, close the pool, and terminate the container.
func NewDataCase(t *testing.T) *DataCase {
	t.Helper()

	ctx := context.Background()

	// 1. Start Postgres container
	ctr, err := testutils.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	dbURL := ctr.ConnectionString

	migrationsDir, err := migrationsDir()
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("failed to get migrations directory: %v", err)
	}

	fmt.Println("Started Postgres container", "dbURL", dbURL, "migrationsDir", migrationsDir)

	// 2. Run migrations on the fresh DB
	if err := utils.RunMigrations("file://"+migrationsDir, dbURL); err != nil {
		// Ensure container is terminated on failure to avoid leaks
		_ = ctr.Terminate(ctx)
		t.Fatalf("failed to run migrations: %v", err)
	}

	// 3. Snapshot DB to enable resets between tests
	if err := ctr.Snapshot(ctx); err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("failed to snapshot database: %v", err)
	}

	// 4. Create pgx pool connection
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		_ = ctr.Terminate(ctx)
		t.Fatalf("failed to create pgx pool: %v", err)
	}

	dc := &DataCase{
		ctx:       ctx,
		container: ctr,
		dbURL:     dbURL,
		pool:      pool,
	}

	// Cleanup: close pool, restore snapshot for next test, terminate container
	t.Cleanup(func() {
		// Close pool first to release any active connections
		dc.pool.Close()
		// Restore snapshot ensures subsequent tests start clean
		_ = dc.container.Restore(dc.ctx)
		_ = dc.container.Terminate(dc.ctx)
	})

	return dc
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

// Pool returns the pgx pool connection.
func (dc *DataCase) Pool() *pgxpool.Pool { return dc.pool }

// URL returns the database connection URL.
func (dc *DataCase) URL() string { return dc.dbURL }

// Reset restores the container to the initial snapshot state.
func (dc *DataCase) Reset(t *testing.T) {
	t.Helper()
	if err := dc.container.Restore(dc.ctx); err != nil {
		t.Fatalf("failed to restore database snapshot: %v", err)
	}
}

// ResetOnCleanup registers a cleanup that restores the DB snapshot after the test.
// Call this inside a subtest to ensure the next subtest starts from a clean state.
func (dc *DataCase) ResetOnCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		// Close current pool to ensure no active sessions block restore
		dc.pool.Close()
		// Restore database snapshot
		_ = dc.container.Restore(dc.ctx)
		// Recreate pool for subsequent test operations
		newPool, err := pgxpool.New(dc.ctx, dc.dbURL)
		if err == nil {
			dc.pool = newPool
		} else {
			t.Logf("failed to recreate pgx pool after restore: %v", err)
		}
	})
}
