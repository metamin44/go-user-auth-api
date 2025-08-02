# Go User Authentication API

A modular user authentication system built in Go with Echo framework, JWT, MySQL, Docker, and advanced features like email password reset, RBAC, rate limiting, supports real email delivery, using `.env` configuration, HTML email templates, structured logging, and Prometheus/Grafana for observability.

---

## 🔧 Features

- ✅ User registration with validation  
- 🔐 Secure login with JWT access and refresh tokens  
- 🔄 Token-based authorization with refresh endpoint 
- 🔑 Password change and reset (via email link) 
- 👤 Profile endpoint  
- 🛠️ User update, delete, and change password  
- 🔑 Forgot/reset password functionality using JWT reset token  
- 🛡️ Role-based access control (`admin`, `user`)  
- 📊 Admin can promote users to admin (`/admin/dashboard`, `/admin/promote`)  
- 📄 Swagger UI API documentation 
- 📧 Email integration for password reset using HTML template  
- 🔐 Separate keys for access and refresh tokens for enhanced security  
- 🐳 Docker Compose support with MySQL  
- 🛠️ Environment configuration via `.env`  
- 🚫 Rate limiting on `/register`, `/login`, and `/forgot-password`
- ✅ Structured logging with Zap + Lumberjack rotation
- 📊 Monitoring with Prometheus and Grafana

---

## 📦 Stack

- **Go (Golang)** – Main backend language  
- **Echo** – HTTP web framework  
- **MySQL** – Database  
- **JWT** – Authentication and authorization  
- **Ozzo-validation** – Input validation  
- **Swagger (swaggo/swag)** – API documentation  
- **Docker & Docker Compose** – Containerization  
- **SMTP (Gmail)** – Email delivery  
- **ulule/limiter** – Rate limiting middleware 
- **Zap + Lumberjack Integration** - Structured logging   

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/metamin44/go-user-auth-api.git
cd go-user-auth-api
```

### 2. Configure Environment Variables

Create a `.env` file in the root:

```env
# Database
DB_USER=your_DB_USER
DB_PASS=your_DB_PASS
DB_HOST=your_DB_HOST
DB_PORT=your_DB_PORT
DB_NAME=your_DB_NAME

# JWT Keys
JWT_SIGN_KEY=your_JWT_SIGN_KEY
JWT_REFRESH_KEY=your_JWT_REFRESH_KEY
JWT_RESET_KEY=your_JWT_RESET_KEY

# Email SMTP
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USERNAME=youremail@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=youremail@gmail.com
ENABLE_EMAIL=true/false
ENABLE_LOGS=true/false

# Rate Limits
RATE_LIMIT_REGISTER=5-S
RATE_LIMIT_LOGIN=10-M
RATE_LIMIT_FORGOT_PASSWORD=3-M
```
**⚠️ Don't commit `.env` — it’s ignored by `.gitignore`.**

---

### 3. Build & Run with Docker

```bash
docker-compose up --build
```

- App 1: First instance of the Go app [http://localhost:8085/swagger/index.html](http://localhost:8085/swagger/index.html)  
- App 2: Second instance of the Go app [http://localhost:8086/swagger/index.html](http://localhost:8086/swagger/index.html)  
- MySQL: Connect to `localhost:3320`
- Prometheus 9091 Metrics collection and query engine
- Grafana 3001 Dashboard and visualization UI

---

## 📫 Password Reset via Email

- Triggered by: `POST /forgot-password`
- Sends a real email with a secure tokenized reset link
- HTML template used for better styling and UX
- Also logs the reset link to console (for dev/testing)

---

## 📦 Logging

### Zap + Lumberjack Integration

This project uses [Uber's Zap](https://github.com/uber-go/zap) for fast, structured logging and [Lumberjack](https://github.com/natefinch/lumberjack) for log rotation.

- Logs are written in **JSON** format to a file: `logs/app.log`
- **Lumberjack** handles automatic rotation, compression, and size limits
- Logging is enabled across:
  - Configuration loading
  - User handlers 
  - Token generation
  - Email sending
  - Middleware (RBAC, rate limiting)
  - Repository/database operations

### Example log output (app.log)

```json
{
  "level": "info",
  "ts": 1721453274.24856,
  "caller": "handler/user.go:45",
  "msg": "User registered successfully",
  "userID": 7,
  "email": "test@example.com"
}
```

---

## 🛠️ Endpoints

### ✅ Public

| Method | Endpoint             | Description                |
|--------|----------------------|----------------------------|
| POST   | `/register`          | Register a new user        |
| POST   | `/login`             | User login                 |
| POST   | `/refresh-token`     | Refresh JWT access token   |
| POST   | `/forgot-password`   | Request password reset     |
| POST   | `/reset-password`    | Reset user password        |

### 🔐 Authenticated (JWT Required)

| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| GET    | `/profile`            | Get current user profile |
| PUT    | `/update`             | Update user profile      |
| PUT    | `/change-password`    | Change user password     |
| DELETE | `/delete`             | Delete user account      |

### 🛡️ Admin Only

| Method | Endpoint              | Description                    |
|--------|-----------------------|--------------------------------|
| GET    | `/admin/dashboard`    | Protected admin dashboard      |
| POST   | `/admin/promote`      | Promote user to admin role     |

---

## 📊 Monitoring with Prometheus & Grafana

Prometheus

Prometheus scrapes metrics from:

app1:8082/metrics

app2:8082/metrics


Prometheus config (prometheus.yml):

global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'apps'
    static_configs:
      - targets: ['app1:8082', 'app2:8082']

Access Prometheus UI: 👉 http://localhost:9091


---

Grafana

Login to Grafana: 👉 http://localhost:3001
Username: admin
Password: admin


---

## 🧪 Unit Testing

Example:

```bash
go test ./handler -v
```

- Includes positive and negative test cases
- Structured response decoding for JSON validation
- Clean database after each test

---

## 📘 API Docs

Swagger is available at:

- `http://localhost:8085/swagger/index.html`
- `http://localhost:8086/swagger/index.html`

---

## 🐳 Docker Overview

 docker-compose.yml includes:

2 App Instances on different ports

MySQL with userdb

Prometheus scraping /metrics from each app

Grafana dashboard for observability


docker-compose down # Stop services
docker-compose down -v # Stop & remove volumes

---

## 🛠 Project Structure

```
├── config
|__ docs
|__ internal
|    └─ metrics
├── handler
|__logger
│   └─ logger.go
├── logs
│   └─ app.log
├── middleware
├── model
├── repository
├── router
├── templates
│   └── reset_email.html
├── tokenutil
├── validationuser
├── main.go
├── go.mod / go.sum
├── .env (ignored)
└── Dockerfile / docker-compose.yml / prometheus.yml
```

---

## 📝 License

This project is open-source and free to use under the MIT License.

---

## 🙋 Author

Created by [amin](https://github.com/metamin44/go-user-auth-api.git)