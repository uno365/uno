package conncase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"uno/services/auth/internal/handler"
	"uno/services/auth/internal/repository/pg"
	"uno/services/auth/internal/service"
	"uno/services/auth/internal/token"
	"uno/services/auth/utils/testutils/datacase"
)

// ConnCase sets up a real Postgres via DataCase and an HTTP test server
// with auth routes wired to real repository and service.
type ConnCase struct {
	ctx    context.Context
	dc     *datacase.DataCase
	server *httptest.Server
}

// NewConnCase initializes Postgres (via DataCase), wires the handler, and starts an httptest.Server.
// The server is closed automatically on test cleanup; the database container cleanup is handled by DataCase.
func NewConnCase(t *testing.T) *ConnCase {
	t.Helper()

	ctx := context.Background()
	dc := datacase.NewDataCase(t)

	// Wire real repository, service, and handler
	repo := pg.NewPostgresUserRepository(dc.Pool())
	jwt := token.NewJWTManager("secret")
	svc := service.NewAuthService(repo, jwt)
	h := handler.NewAuthHandler(svc)

	mux := http.NewServeMux()
	mux.HandleFunc("/register", h.Register)
	mux.HandleFunc("/login", h.Login)

	srv := httptest.NewServer(mux)

	cc := &ConnCase{ctx: ctx, dc: dc, server: srv}

	// Close server when test completes; DB cleanup handled by DataCase.
	t.Cleanup(func() { cc.server.Close() })

	return cc
}

// URL returns the base URL of the test server.
func (cc *ConnCase) URL() string { return cc.server.URL }

// Pool exposes the underlying pgx pool for advanced use if needed.
func (cc *ConnCase) Pool() *pgxpool.Pool { return cc.dc.Pool() }

// ResetOnCleanup resets the DB snapshot after the subtest; use for isolation between subtests.
func (cc *ConnCase) ResetOnCleanup(t *testing.T) {
	t.Helper()
	// Register our cleanup first so DataCase reset runs before rebuilding server (LIFO order)
	t.Cleanup(func() {
		// Close existing server so no requests use old pool
		cc.server.Close()
		// Now, DataCase's cleanup should have restored and recreated the pool.
		// Rewire handler and restart server using the fresh pool.
		repo := pg.NewPostgresUserRepository(cc.dc.Pool())
		jwt := token.NewJWTManager("secret")
		svc := service.NewAuthService(repo, jwt)
		h := handler.NewAuthHandler(svc)

		mux := http.NewServeMux()
		mux.HandleFunc("/register", h.Register)
		mux.HandleFunc("/login", h.Login)
		cc.server = httptest.NewServer(mux)
	})
	// Register DataCase reset after our cleanup to ensure it runs first
	cc.dc.ResetOnCleanup(t)
}
