package handler

import (
	"fmt"
	"reg/config"
	"reg/model"
	"reg/repository"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func insertKnownUser(handler *UserHandler) {

	db := handler.Repo.DB

	db.Where("email = ?", "testuser@example.com").Delete(&model.User{})
	db.Where("email = ?", "newuser@example.com").Delete(&model.User{})
	db.Where("phone = ?", "09123456789").Delete(&model.User{})

	hash, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)

	_ = handler.Repo.CreateUser(&model.User{
		ID:       1,
		Name:     "Test User",
		Email:    "testuser@example.com",
		Phone:    "09123456789",
		Password: string(hash),
	})
}

func setup(t *testing.T) (*echo.Echo, *UserHandler) {
	t.Helper()

	// Load .env from project root
	err := godotenv.Load("../.env")
	if err != nil {
		t.Fatalf("❌ failed to load .env: %v", err)
	}

	// Load config
	cfg := config.LoadConfig()

	// Initialize a no-op zap logger (silent, test-friendly)
	logger, _ := zap.NewDevelopment() // or zap.NewExample() / zap.NewNop()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Initialize repo
	repo, err := repository.NewUserRepo(cfg)
	if err != nil {
		t.Fatalf("❌ could not connect to database: %v", err)
	}

	// ✅ Inject logger into UserHandler
	handler := NewUserHandler(repo, cfg, logger)

	// Insert known user before tests
	insertKnownUser(handler)

	e := echo.New()
	return e, handler
}

func generateResetToken(t *testing.T, email, secret string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": email,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"jti": fmt.Sprintf("%d", time.Now().UnixNano()), // Unique identifier
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create reset token: %v", err)
	}
	return signedToken
}

func generateRefreshToken(userID uint, role string, secret string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func insertPromotableUser(t *testing.T, h *UserHandler, email, password, role string) *model.User {

	db := h.Repo.DB
	db.Where("email = ?", "promoteuser@example.com").Delete(&model.User{})

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("❌ failed to hash password: %v", err)
	}

	user := &model.User{
		Name:     "Promote User",
		Email:    email,
		Phone:    "0999999999",
		Password: string(hashed),
		Role:     role,
	}

	if err := h.Repo.CreateUser(user); err != nil {
		t.Fatalf("❌ failed to insert promotable user: %v", err)
	}

	return user
}

// generateTestJWT creates a valid JWT token for testing
func generateTestJWT(userID uint) string {
	// Replace with the secret you use in your real config
	secret := []byte("supersecretkey") // ✅ MUST match your config.AccessTokenSecret

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 1).Unix(), // expires in 1 hour
	})
	tokenString, _ := token.SignedString(secret)
	return tokenString
}

// Helper to generate JWT token with role claim
func generateAdminTestJWT(role string, secret string) string {
	claims := jwt.MapClaims{
		"sub":  "testuser@example.com",
		"role": role,
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString([]byte(secret))
	return tokenStr
}
