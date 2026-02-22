# Auth Service

A lightweight authentication microservice built with Go, providing user registration, login, token refresh, and logout functionality with JWT-based authentication.

## Features

- User registration with email/password
- User login with JWT access tokens
- Token refresh with rotating refresh tokens (stored in HTTP-only cookies)
- Session management with logout
- Password hashing with bcrypt
- PostgreSQL database with automatic migrations
- Hexagonal architecture (ports, adapters, domain, service)
- Docker support
- Comprehensive test coverage (unit + integration tests)

## Tech Stack

- **Framework**: [Chi](https://github.com/go-chi/chi) router
- **Database**: PostgreSQL with [pgx](https://github.com/jackc/pgx) driver
- **Authentication**: [JWT](https://github.com/golang-jwt/jwt)
- **Migrations**: [golang-migrate](https://github.com/golang-migrate/migrate)
- **Testing**: [testify](https://github.com/stretchr/testify) + [testcontainers-go](https://github.com/testcontainers/testcontainers-go)

## Project Structure

```
├── cmd/http/                    # HTTP server entrypoint
├── internal/
│   ├── adapter/                 # External interfaces (driven/driving adapters)
│   │   ├── db/postgres/         # PostgreSQL implementation
│   │   │   ├── migrations/      # SQL migration files
│   │   │   └── repo/            # Repository implementations
│   │   ├── handler/http/        # HTTP handlers
│   │   │   └── middleware/      # HTTP middleware
│   │   └── token/               # JWT token implementation
│   └── core/                    # Business logic (domain layer)
│       ├── domain/              # Domain models and errors
│       ├── port/                # Interfaces (ports)
│       └── service/             # Business logic services
└── testdata/                    # Test utilities and helpers
```

## Getting Started

### Prerequisites

- Go 1.25+
- PostgreSQL
- Docker (optional, required for integration tests)

### Environment Variables

Create a `.env` file in the project root:

```env
DATABASE_URL=postgres://user:password@localhost:5432/auth_db?sslmode=disable
JWT_SECRET=your-secret-key
PORT=4000
CORS_ORIGINS=http://localhost:3000
TRUST_PROXY=false
```

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `JWT_SECRET` | Secret key for signing JWTs | Required |
| `PORT` | Server port | `4000` |
| `CORS_ORIGINS` | Comma-separated list of allowed origins | `http://localhost:3000` |
| `TRUST_PROXY` | Trust X-Forwarded-For headers (set `true` behind reverse proxy) | `false` |

### Running Locally

```bash
# Install dependencies
go mod download

# Run the server
go run ./cmd/http
```

### Running with Docker

```bash
# Build the image
docker build -t auth-service .

# Run the container
docker run -p 4000:4000 \
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

**Response (201 Created):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

Sets `refresh_token` as HTTP-only cookie.

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
  "access_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

Sets `refresh_token` as HTTP-only cookie.

### Refresh Token

```
POST /refresh
```

Requires `refresh_token` cookie (set automatically by login/register).

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

Rotates the refresh token cookie.

### Logout

```
POST /logout
```

Requires `refresh_token` cookie.

**Response (200 OK):**
```json
{
  "message": "logged out successfully"
}
```

Revokes the session and clears the refresh token cookie.

## Token Details

- **Access Token**: Valid for 15 minutes
- **Refresh Token**: Valid for 7 days, stored in HTTP-only secure cookie
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
# Run unit tests with coverage
make test

# Run only integration tests
go test ./cmd/http/... -tags=integration -v
```

Tests use [testcontainers-go](https://github.com/testcontainers/testcontainers-go) to spin up PostgreSQL containers for integration testing.

## License

MIT
