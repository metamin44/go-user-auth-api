# Go User Authentication API

A modular user authentication system built in Go with Echo framework, JWT, MySQL, Docker, and advanced features like email password reset, RBAC, rate limiting, supports real email delivery, using `.env` configuration, HTML email templates and structured logging.

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

- App 1: [http://localhost:8085/swagger/index.html](http://localhost:8085/swagger/index.html)  
- App 2: [http://localhost:8086/swagger/index.html](http://localhost:8086/swagger/index.html)  
- MySQL: Connect to `localhost:3320`

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

## 🛠 Project Structure

```
├── config
├── handler
|__logger
│   └── logger
├── logs
│   └── app.log
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
└── Dockerfile / docker-compose.yml
```

---

## 📝 License

This project is open-source and free to use under the MIT License.

---

## 🙋 Author

Created by [amin](https://github.com/metamin44/go-user-auth-api.git)