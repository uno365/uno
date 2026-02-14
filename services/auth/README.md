# Auth Service

A lightweight authentication microservice built with Go, providing user registration and login functionality with JWT-based authentication.

## Features

- User registration with email/password
- User login with JWT access and refresh tokens
- Password hashing with bcrypt
- PostgreSQL database with automatic migrations
- Clean architecture (domain, repository, service, handler layers)
- Docker support

## Tech Stack

- **Framework**: [Gin](https://github.com/gin-gonic/gin)
- **Database**: PostgreSQL with [pgx](https://github.com/jackc/pgx) driver
- **Authentication**: [JWT](https://github.com/golang-jwt/jwt)
- **Migrations**: [golang-migrate](https://github.com/golang-migrate/migrate)
- **Testing**: [testcontainers-go](https://github.com/testcontainers/testcontainers-go)

## Project Structure

```
├── cmd/server/          # Application entrypoint
├── internal/
│   ├── domain/          # Domain models and errors
│   ├── handler/         # HTTP handlers
│   ├── repository/      # Data access layer
│   │   └── pg/          # PostgreSQL implementation
│   ├── service/         # Business logic
│   └── token/           # JWT token management
├── migrations/          # SQL migration files
└── utils/               # Utility functions
```

## Getting Started

### Prerequisites

- Go 1.25+
- PostgreSQL
- Docker (optional)

### Environment Variables

Create a `.env` file in the project root:

```env
DATABASE_URL=postgres://user:password@localhost:5432/auth_db?sslmode=disable
JWT_SECRET=your-secret-key
PORT=8080
```

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `JWT_SECRET` | Secret key for signing JWTs | Required |
| `PORT` | Server port | `8080` |

### Running Locally

```bash
# Install dependencies
go mod download

# Run the server
go run ./cmd/server
```

### Running with Docker

```bash
# Build the image
docker build -t auth-service .

# Run the container
docker run -p 8080:8080 \
  -e DATABASE_URL="postgres://user:password@host:5432/auth_db" \
  -e JWT_SECRET="your-secret-key" \
  auth-service
```

## API Endpoints

### Register

```
POST /register
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Login

```
POST /login
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

## Token Details

- **Access Token**: Valid for 15 minutes
- **Refresh Token**: Valid for 7 days
- **Algorithm**: HS256

## Database Migrations

```bash
# Run migrations
make db.migrate

# Rollback last migration
make db.rollback

# Create new migration
make db.migration.create name=migration_name
```

## Testing

```bash
# Run all tests with coverage
make test

# Or directly with go
go test ./... --cover
```

Tests use [testcontainers-go](https://github.com/testcontainers/testcontainers-go) to spin up PostgreSQL containers for integration testing.

## License

MIT
