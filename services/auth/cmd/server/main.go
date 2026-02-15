// Package main is the entry point for the auth service.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"uno/services/auth/internal/handler"
	"uno/services/auth/internal/middleware"
	"uno/services/auth/internal/repository"
	"uno/services/auth/internal/service"
	"uno/services/auth/internal/token"
	"uno/services/auth/utils"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	chimw "github.com/go-chi/chi/v5/middleware"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

type Server struct {
	Router       *chi.Mux
	DB           *pgxpool.Pool
	DATABASE_URL string
	JWT_SECRET   string
	PORT         string
}

func CreateNewServer() *Server {
	server := &Server{}
	server.Router = chi.NewRouter()
	return server
}

func (server *Server) MountEnv() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		slog.Default().Warn("Error loading .env file")
	}

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
		port = "8080"
	}

	server.PORT = port

}

func (server *Server) MountDB() {

	// Run database migrations
	err := utils.RunMigrations("file://migrations", server.DATABASE_URL)
	if err != nil {
		slog.Default().Error("Failed to run migrations", "error", err)
	}

	// Initialize database connection
	ctx := context.Background()

	db, err := pgxpool.New(ctx, server.DATABASE_URL)

	if err != nil {
		slog.Default().Error("Failed to connect to database", "error", err)
	}

	server.DB = db

}

func (server *Server) MountHandlers() {

	// Initialize repositories, services, and handlers
	userRepo := repository.NewUserRepository(server.DB)
	jwtManager := token.NewJWTManager(server.JWT_SECRET)
	authService := service.NewAuthService(userRepo, jwtManager)
	authHandler := handler.NewAuthHandler(authService)

	// middlewares
	c := cors.New(cors.Options{AllowedOrigins: []string{"*"}})
	server.Router.Use(c.Handler)
	server.Router.Use(chimw.RequestID)
	server.Router.Use(chimw.Logger)
	server.Router.Use(chimw.Recoverer)
	server.Router.Use(middleware.ErrorHandler)

	// routes
	server.Router.Post("/register", authHandler.Register)
	server.Router.Post("/login", authHandler.Login)
}

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
	server.MountHandlers()
	server.Run()
}
