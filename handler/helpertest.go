package handler

import (
	"os"
	"reg/config"
	"reg/model"
	"reg/repository"
	"reg/tokenutil"
	"testing"

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

	// Load .env if available (local development).
	// CI environments provide configuration through environment variables.
	if err := godotenv.Load("../.env"); err != nil {
		if !os.IsNotExist(err) {
			t.Fatalf("failed to load .env: %v", err)
		}
	}

	// Load config
	cfg := config.LoadConfig()
	// Tests run on the host machine, not inside Docker.
	cfg.Database.Host = "127.0.0.1"
	cfg.Database.Port = "3320"

	// Initialize a no-op zap logger (silent, test-friendly)
	logger, err := zap.NewDevelopment() // or zap.NewExample() / zap.NewNop()
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

func generateResetToken(t *testing.T, email string, cfg *config.Config) string {
	t.Helper()

	signedToken, err := tokenutil.GenerateResetToken(email, cfg)
	if err != nil {
		t.Fatalf("Failed to create reset token: %v", err)
	}

	return signedToken
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

func generateTestJWT(t *testing.T, userID uint, cfg *config.Config) string {
	t.Helper()

	token, err := tokenutil.GenerateAccessToken(userID, "user", 1, cfg)
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	return token
}

// generateAdminTestJWT creates a valid access token for admin tests.
func generateAdminTestJWT(t *testing.T, role string, cfg *config.Config) string {
	t.Helper()

	token, err := tokenutil.GenerateAccessToken(1, role, 1, cfg)
	if err != nil {
		t.Fatalf("Failed to generate admin test token: %v", err)
	}

	return token
}
