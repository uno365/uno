// Package main is the entry point for the auth service.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"uno/services/auth/internal/handler"
	"uno/services/auth/internal/middleware"
	"uno/services/auth/internal/repository/pg"
	"uno/services/auth/internal/service"
	"uno/services/auth/internal/token"
	"uno/services/auth/utils"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// SetupAuthRouter initializes and configures the Chi router with all auth routes.
func SetupAuthRouter(db *pgxpool.Pool, secret string) *chi.Mux {

	// Initialize repositories, services, and handlers
	userRepo := pg.NewPostgresUserRepository(db)
	jwtManager := token.NewJWTManager(secret)
	authService := service.NewAuthService(userRepo, jwtManager)
	authHandler := handler.NewAuthHandler(authService)

	// Setup Chi router with middleware
	router := chi.NewRouter()
	router.Use(chimw.Logger)
	router.Use(chimw.Recoverer)
	router.Use(middleware.ErrorHandler)
	router.Post("/register", authHandler.Register)
	router.Post("/login", authHandler.Login)
	return router
}

func main() {

	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		slog.Default().Warn("Error loading .env file")
	}

	// Load DATABASE_URL
	dbURL := os.Getenv("DATABASE_URL")

	if dbURL == "" {
		slog.Default().Error("DATABASE_URL is not set")
		return
	}

	// Load JWT_SECRET
	secret := os.Getenv("JWT_SECRET")

	if secret == "" {
		slog.Default().Error("JWT_SECRET is not set")
		return
	}

	// Load PORT
	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	// Run database migrations
	err = utils.RunMigrations("file://migrations", dbURL)
	if err != nil {
		slog.Default().Error("Failed to run migrations", "error", err)
	}

	// Initialize database connection
	ctx := context.Background()

	db, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		slog.Default().Error("Failed to connect to database", "error", err)
	}

	// Setup Chi router
	router := SetupAuthRouter(db, secret)

	slog.Default().Info("Auth service running on :" + port)

	if err := http.ListenAndServe(":"+port, router); err != nil {
		slog.Default().Error("Failed to start server", "error", err)
	}

}
