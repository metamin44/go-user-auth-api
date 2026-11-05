# Go User Authentication API

A modular RESTful authentication backend built with **Go and Echo**, backed by **MySQL** and **GORM**. The project includes JWT-based authentication, refresh token rotation, session management, role-based access control, password recovery with SMTP email delivery, rate limiting, structured logging, API documentation, and monitoring with Prometheus and Grafana.

The application is containerized with Docker Compose and supports running multiple application instances.

## Features

### Authentication and account management

- User registration with input validation.
- Secure password hashing using bcrypt.
- Login with JWT access and refresh tokens.
- Separate signing keys for access, refresh, and password-reset tokens.
- Protected user profile endpoint.
- Update and delete user accounts.
- Change password.
- Forgot-password and password-reset workflows.
- HTML email template for password-reset messages.
- HTML password-reset page with password confirmation.
- SMTP integration for real email delivery.

### Session and token security

- Independent login sessions.
- Refresh token rotation.
- Refresh token hashes stored in the database instead of raw refresh tokens.
- Refresh token reuse detection.
- Session expiration and revocation.
- Token versioning to invalidate previously issued tokens after security-sensitive account changes.
- Password-reset token hashes stored and verified in the database.
- Single-use, time-limited password-reset tokens.

### Authorization and protection

- Role-based access control (RBAC) for `user` and `admin` roles.
- Admin-only dashboard and user promotion endpoints.
- Rate limiting for registration, login, and forgot-password requests.
- Request validation using Ozzo Validation.

### Observability and documentation

- Structured JSON logging with Uber Zap.
- Log rotation using Lumberjack.
- Prometheus application metrics.
- Grafana dashboard support.
- Swagger API documentation.
- HTTP request logging without query strings, helping prevent sensitive reset tokens from appearing in access logs.

## Tech Stack

| Technology        | Purpose                          |
| ----------------- | -------------------------------- |
| Go                | Backend programming language     |
| Echo              | HTTP web framework               |
| MySQL             | Relational database              |
| GORM              | ORM and database access          |
| JWT               | Authentication and authorization |
| bcrypt            | Password hashing                 |
| SHA-256           | Token hashing                    |
| Ozzo Validation   | Request validation               |
| Swagger / Swaggo  | API documentation                |
| Docker Compose    | Application orchestration        |
| SMTP              | Password-reset email integration |
| HTML / JavaScript | Password-reset user interface    |
| Zap               | Structured logging               |
| Lumberjack        | Log rotation                     |
| Prometheus        | Metrics collection               |
| Grafana           | Metrics visualization            |

## Architecture Overview

The application follows a modular monolithic architecture:

- **Router:** Registers public, authenticated, and admin-only routes.
- **Handler:** Processes HTTP requests and responses.
- **Repository:** Handles database operations.
- **Model:** Defines database entities, including users and sessions.
- **Middleware:** Handles JWT authentication, authorization, rate limiting, and metrics.
- **Token utilities:** Generate and validate authentication and password-reset tokens.
- **Validation:** Centralizes request validation.
- **Configuration:** Loads application settings from environment variables.

The Docker Compose setup runs two application instances connected to the same MySQL database, alongside Prometheus and Grafana.

## Getting Started

### Prerequisites

- Go (version specified in `go.mod`).
- Docker Desktop or Docker Engine with Docker Compose.
- Git.

### 1. Clone the repository

```bash
git clone https://github.com/metamin44/go-user-auth-api.git
cd go-user-auth-api
```

### 2. Configure environment variables

Create your local environment file from the example:

```bash
cp .env.example .env
```

Update `.env` with your own configuration.

Important settings include:

| Variable group        | Description                           |
| --------------------- | ------------------------------------- |
| `APP_PORT`            | Application listening port            |
| `DB_*`                | MySQL connection settings             |
| `MYSQL_ROOT_PASSWORD` | MySQL root password                   |
| `JWT_SIGN_KEY`        | Access-token signing key              |
| `JWT_REFRESH_KEY`     | Refresh-token signing key             |
| `JWT_RESET_KEY`       | Password-reset token signing key      |
| `EMAIL_*`             | SMTP server and sender configuration  |
| `ENABLE_EMAIL`        | Enable or disable email delivery      |
| `ENABLE_LOGS`         | Enable or disable application logging |
| `RESET_PASSWORD_URL`  | Password-reset page URL               |
| `RATE_LIMIT_*`        | Rate-limiting configuration           |
| `GF_SECURITY_*`       | Grafana administrator credentials     |

Use strong, unique secret values for JWT keys and passwords. Configure valid SMTP credentials if you want to enable email delivery.

**Never commit your actual `.env` file or production secrets.** The local environment file is excluded through `.gitignore`.

### 3. Build and start the services

```bash
docker compose up --build -d
```

This starts:

| Service                 | Address                                  |
| ----------------------- | ---------------------------------------- |
| Application instance 1  | http://localhost:8085                    |
| Application instance 2  | http://localhost:8086                    |
| Swagger UI (instance 1) | http://localhost:8085/swagger/index.html |
| Swagger UI (instance 2) | http://localhost:8086/swagger/index.html |
| MySQL                   | `localhost:3320`                         |
| Prometheus              | http://localhost:9091                    |
| Grafana                 | http://localhost:3001                    |

The first application instance runs database migrations. The second instance starts without running migrations.

To check service status:

```bash
docker compose ps
```

To view application logs:

```bash
docker compose logs -f app1
```

To stop the services:

```bash
docker compose down
```

To stop the services and remove named volumes:

```bash
docker compose down -v
```

**Note:** Removing volumes can delete persistent data, including Grafana storage.

## API Endpoints

The following table summarizes the routes registered by the application.

### Public endpoints

| Method | Endpoint           | Description                               |
| ------ | ------------------ | ----------------------------------------- |
| POST   | `/register`        | Register a new user                       |
| POST   | `/login`           | Authenticate a user                       |
| POST   | `/refresh`         | Rotate refresh token and issue new tokens |
| POST   | `/forgot-password` | Request a password-reset link             |
| GET    | `/reset-password`  | Display the password-reset page           |
| POST   | `/reset-password`  | Reset the user's password                 |

### Authenticated endpoints

These endpoints require a valid access token in the `Authorization` header.

| Method | Endpoint                | Description                             |
| ------ | ----------------------- | --------------------------------------- |
| GET    | `/auth/profile`         | Get the authenticated user's profile    |
| PUT    | `/auth/update`          | Update the user's profile               |
| DELETE | `/auth/delete`          | Delete the authenticated user's account |
| POST   | `/auth/change-password` | Change the user's password              |

Example authorization header:

```http
Authorization: Bearer YOUR_ACCESS_TOKEN
```

### Admin-only endpoints

These endpoints require an authenticated administrator.

| Method | Endpoint           | Description                     |
| ------ | ------------------ | ------------------------------- |
| GET    | `/admin/dashboard` | Access the admin dashboard      |
| PUT    | `/admin/promote`   | Promote a user to administrator |

## Password Reset Workflow

The project implements an end-to-end password recovery workflow.

1. A user submits a password-reset request.
2. The application generates a time-limited JWT reset token.
3. The reset link is prepared using the configured reset URL.
4. When SMTP email delivery is enabled and configured, the application sends the reset link to the user's email address.
5. The user opens the link and sees an HTML password-reset form.
6. The user enters and confirms a new password.
7. The browser sends the token and new password to the reset endpoint.
8. The backend validates the JWT and checks the corresponding token hash and expiration in the database.
9. The password is securely hashed with bcrypt and updated.
10. The reset token is invalidated, and previously issued authentication tokens and sessions are invalidated according to the application's token and session management logic.

Reset tokens have a **15-minute validity period**.

SMTP email delivery is optional and controlled through the `ENABLE_EMAIL` environment variable.

- When `ENABLE_EMAIL=true`, password-reset links are delivered through SMTP.
- When `ENABLE_EMAIL=false`, no email is sent.
- Reset tokens are stored as hashes in the database and are not logged in plaintext.

### Password Reset Security

The implementation includes several security measures:

- Reset tokens are time-limited.
- Reset token hashes are stored in the database.
- The token must pass JWT validation and database verification.
- Expired, invalid, or previously used reset links are rejected.
- The password-reset page uses an embedded HTML template.
- The token is removed from the browser address bar after the page loads.
- The page uses `no-referrer` and `no-store` security settings.
- HTTP request logs use the request path rather than the full URI, avoiding accidental logging of query-string tokens.

The HTML email template is located at:

```text
tokenutil/templates/reset_email.html
```

The password-reset page template is located at:

```text
handler/templates/reset_password.html
```

## Session Management and Token Rotation

Each successful login creates an independent user session.

The authentication flow includes:

- Shorter-lived access tokens and longer-lived refresh tokens.
- Separate signing keys for different token types.
- Refresh token rotation when a refresh request succeeds.
- SHA-256 hashes of refresh tokens stored in the database.
- Detection of refresh token reuse.
- Session expiration and revocation.
- Token-version checks to invalidate previously issued tokens after relevant account changes.

This design helps reduce the impact of stolen or replayed refresh tokens.

## Security Considerations

The project applies several security practices:

- Passwords are hashed using bcrypt rather than stored as plain text.
- JWT signing keys are separated by token purpose.
- Refresh and password-reset tokens are verified against database state.
- Sensitive tokens are not included in HTTP access-log query strings.
- Password-reset tokens expire and cannot be reused after successful completion.
- Configuration secrets are loaded through environment variables.
- `.env` is excluded from version control.

This project is an educational and portfolio backend implementation. A production deployment should also include environment-specific security configuration, HTTPS, secret management, monitoring, and deployment hardening.

## Monitoring with Prometheus and Grafana

The application exposes metrics through:

```text
/metrics
```

Prometheus is configured to scrape both application instances:

```yaml
scrape_configs:
  - job_name: "apps"
    static_configs:
      - targets: ["app1:8082", "app2:8082"]
```

The scrape interval is configured in `prometheus.yml`.

Open the Prometheus interface:

http://localhost:9091

Open Grafana:

http://localhost:3001

Use the administrator credentials configured through `GF_SECURITY_ADMIN_USER` and `GF_SECURITY_ADMIN_PASSWORD` in `.env`.

## Logging

The application uses Uber Zap for structured logging and Lumberjack for log rotation.

Logging features include:

- Structured JSON application logs.
- File-based logging.
- Automatic log rotation and compression.
- Logging across application handlers, middleware, token operations, and database-related operations.
- HTTP request logging with method, path, status, latency, and remote IP.

The HTTP request logger records the request path instead of the complete URI. This prevents query-string values, such as password-reset tokens, from being exposed in access logs.

The configured log file is:

```text
logs/app.log
```

## Running Tests

The test suite includes handler, middleware, repository, and validation tests.

**Database prerequisite:** Handler and repository tests connect to MySQL. The handler test setup loads `.env` from the project root and connects to the database at `127.0.0.1:3320`.

First, make sure `.env` is configured and start the database:

```bash
docker compose up -d db
```

Then, from the project root, run:

```bash
go test -count=1 ./...
```

Run an individual package's tests:

```bash
go test -count=1 ./handler -v
go test -count=1 ./middleware -v
go test -count=1 ./repository -v
go test -count=1 ./validationuser -v
```

## API Documentation

Swagger documentation is generated with Swaggo and is available after starting the application:

- http://localhost:8085/swagger/index.html
- http://localhost:8086/swagger/index.html

Use Swagger UI to explore the API endpoints and test supported requests.

## Project Structure

```text
.
├── config/
│   └── config.go
├── docs/
│   ├── docs.go
│   ├── swagger.json
│   └── swagger.yaml
├── handler/
│   ├── templates/
│   │   └── reset_password.html
│   ├── *_test.go
│   └── userhandler.go
├── internal/
│   └── metrics/
│       └── metrics.go
├── logger/
│   └── logger.go
├── middleware/
│   ├── jwtmiddleware.go
│   ├── metrics.go
│   ├── ratelimiter.go
│   └── *_test.go
├── model/
│   ├── request/
│   │   └── user.go
│   ├── user.go
│   └── user_session.go
├── repository/
│   ├── user.go
│   └── user_test.go
├── router/
│   └── router.go
├── tokenutil/
│   ├── email.go
│   ├── token.go
│   └── templates/
│       └── reset_email.html
├── validationuser/
│   ├── validator.go
│   └── validator_test.go
├── main.go
├── Dockerfile
├── docker-compose.yml
├── prometheus.yml
├── .env.example
├── .gitignore
├── go.mod
└── go.sum
```

## Author

GitHub: [metamin44](https://github.com/metamin44)

## License

No license has been specified yet.
