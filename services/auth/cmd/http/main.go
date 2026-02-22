// Package main is the entry point for the auth service.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/joho/godotenv"

	"uno/services/auth/internal/adapter/db/postgres"
	"uno/services/auth/internal/adapter/db/postgres/repo"
	httpHandler "uno/services/auth/internal/adapter/handler/http"
	"uno/services/auth/internal/adapter/handler/http/middleware"
	tokenAdapter "uno/services/auth/internal/adapter/token"
	"uno/services/auth/internal/core/service"
)

type Server struct {
	Router       *chi.Mux
	DB           *postgres.DB
	DATABASE_URL string
	JWT_SECRET   string
	PORT         string
	CORS_ORIGINS []string
	TRUST_PROXY  bool
}

// CreateNewServer initializes a new Server instance with a chi router.
func CreateNewServer() *Server {
	server := &Server{}
	server.Router = chi.NewRouter()
	return server
}

// MountEnv loads environment variables and sets server configuration fields.
func (server *Server) MountEnv() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		slog.Default().Warn("Error loading .env file")
	}

	// Load DATABASE_URL
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		slog.Default().Error("DATABASE_URL is not set")
		return
	}

	server.DATABASE_URL = databaseURL

	// Load JWT_SECRET
	secret := os.Getenv("JWT_SECRET")

	if secret == "" {
		slog.Default().Error("JWT_SECRET is not set")
		return
	}

	server.JWT_SECRET = secret

	// Load PORT
	port := os.Getenv("PORT")

	if port == "" {
		port = "4000"
	}

	server.PORT = port

	// Load CORS_ORIGINS (comma-separated list of allowed origins)
	// Default to localhost for development
	corsOrigins := os.Getenv("CORS_ORIGINS")
	if corsOrigins == "" {
		server.CORS_ORIGINS = []string{"http://localhost:3000"}
	} else {
		server.CORS_ORIGINS = strings.Split(corsOrigins, ",")
		for i := range server.CORS_ORIGINS {
			server.CORS_ORIGINS[i] = strings.TrimSpace(server.CORS_ORIGINS[i])
		}
	}

	// Load TRUST_PROXY (set to "true" when behind a reverse proxy)
	// Default to false for security
	server.TRUST_PROXY = os.Getenv("TRUST_PROXY") == "true"

}

// MountDB initializes the database connection and runs migrations.
func (server *Server) MountDB() {
	ctx := context.Background()
	db, err := postgres.NewDB(ctx, server.DATABASE_URL)

	if err != nil {
		slog.Default().Error("Failed to connect to database", "error", err)
		return
	}

	err = db.Migrate()

	if err != nil {
		slog.Default().Error("Failed to run migrations", "error", err)
		return
	}

	server.DB = db

}

// MountMiddlewares sets up CORS and common middlewares for the router.
func (server *Server) MountMiddlewares() {

	corsMW := cors.New(cors.Options{
		AllowedOrigins:   server.CORS_ORIGINS,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	})

	server.Router.Use(corsMW.Handler)
	server.Router.Use(chimw.RequestID)
	server.Router.Use(chimw.Logger)
	server.Router.Use(chimw.Recoverer)
	server.Router.Use(middleware.ErrorHandler)
}

// MountHandlers sets up the HTTP handlers for authentication routes.
func (server *Server) MountHandlers() {

	userRepo := repo.NewUserRepo(server.DB)
	sessionRepo := repo.NewSessionRepo(server.DB)

	tokenManager := tokenAdapter.NewJWT(server.JWT_SECRET)
	authService := service.NewAuthService(userRepo, sessionRepo, tokenManager)
	authHandler := httpHandler.NewAuthHandler(authService, server.TRUST_PROXY)

	// routes
	server.Router.Post("/register", authHandler.Register)
	server.Router.Post("/login", authHandler.Login)
	server.Router.Post("/refresh", authHandler.Refresh)
	server.Router.Post("/logout", authHandler.Logout)
}

// Run starts the HTTP server on the configured port.
func (server *Server) Run() {
	slog.Default().Info("Auth service running on :" + server.PORT)

	if err := http.ListenAndServe(":"+server.PORT, server.Router); err != nil {
		slog.Default().Error("Failed to start server", "error", err)
	}
}

func main() {
	server := CreateNewServer()
	server.MountEnv()
	server.MountDB()
	server.MountMiddlewares()
	server.MountHandlers()
	server.Run()
}
