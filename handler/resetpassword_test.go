package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestResetPassword(t *testing.T) {
	e, h := setup(t)

	// Step 1: Generate a reset token for the known user
	userEmail := "testuser@example.com"
	resetToken := generateResetToken(t, userEmail, h.Cfg.JWT.ResetKey)

	// Step 2: Save the reset token and expiry into the user record
	expiry := time.Now().Add(15 * time.Minute)
	updates := map[string]interface{}{
		"reset_token":        resetToken,
		"reset_token_expiry": expiry,
	}
	user, _ := h.Repo.GetUserByEmail(userEmail)
	_ = h.Repo.UpdateUser(user.ID, updates)

	// Step 3: Prepare request body with reset token and new password
	reqBody := fmt.Sprintf(`{
        "token": "%s",
        "new_password": "NewPassword123!"
    }`, resetToken)

	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Step 4: Call the handler
	err := h.ResetPassword(c)

	// Step 5: Assertions
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Password successfully reset")

	// Step 6: Verify password was updated in DB
	updatedUser, _ := h.Repo.GetUserByEmail(userEmail)
	err = bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte("NewPassword123!"))
	assert.NoError(t, err)

	// Step 7: Ensure token and expiry were cleared
	assert.Nil(t, updatedUser.ResetToken)
	assert.Nil(t, updatedUser.ResetTokenExpiry)
}

func TestResetPassword_InvalidToken(t *testing.T) {
	e, h := setup(t)

	reqBody := `{
        "token": "invalid.token.string",
        "new_password": "AnotherPass123!"
    }`

	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.ResetPassword(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid or expired token")
}

func createExpiredToken(t *testing.T, email, secret string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": email,
		"exp": time.Now().Add(-10 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create expired token: %v", err)
	}
	return signedToken
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	e, h := setup(t)

	// Create an expired token
	expiredToken := createExpiredToken(t, "testuser@example.com", h.Cfg.JWT.ResetKey)

	// Manually save it to the DB
	user, _ := h.Repo.GetUserByEmail("testuser@example.com")
	updates := map[string]interface{}{
		"reset_token":        expiredToken,
		"reset_token_expiry": time.Now().Add(-1 * time.Minute),
	}
	_ = h.Repo.UpdateUser(user.ID, updates)

	reqBody := fmt.Sprintf(`{
        "token": "%s",
        "new_password": "ExpiredTokenPass123!"
    }`, expiredToken)

	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.ResetPassword(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid or expired token")
}

func TestResetPassword_MismatchedToken(t *testing.T) {
	e, h := setup(t)

	// Save valid token in DB
	validToken := generateResetToken(t, "testuser@example.com", h.Cfg.JWT.ResetKey)
	user, _ := h.Repo.GetUserByEmail("testuser@example.com")
	_ = h.Repo.UpdateUser(user.ID, map[string]interface{}{
		"reset_token":        validToken,
		"reset_token_expiry": time.Now().Add(15 * time.Minute),
	})

	// Use a different (mismatched) token
	wrongToken := generateResetToken(t, "testuser@example.com", h.Cfg.JWT.ResetKey)

	reqBody := fmt.Sprintf(`{
        "token": "%s",
        "new_password": "Mismatch123!"
    }`, wrongToken)

	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.ResetPassword(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Token is invalid or expired")
}

func TestResetPassword_UserNotFound(t *testing.T) {
	e, h := setup(t)

	// Create token for a non-existent email
	token := generateResetToken(t, "nonexistent@example.com", h.Cfg.JWT.ResetKey)

	reqBody := fmt.Sprintf(`{
        "token": "%s",
        "new_password": "DoesNotMatter123!"
    }`, token)

	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.ResetPassword(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "User not found")
}
