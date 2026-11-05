package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reg/model"
	"reg/tokenutil"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestResetPassword(t *testing.T) {
	e, h := setup(t)

	// Step 1: Generate a reset token for the known user
	userEmail := "testuser@example.com"
	resetToken := generateResetToken(t, userEmail, h.Cfg)

	// Step 2: Save the reset token and expiry into the user record
	expiry := time.Now().Add(15 * time.Minute)

	user, lookupErr := h.Repo.GetUserByEmail(userEmail)
	assert.NoError(t, lookupErr)
	assert.NotNil(t, user)

	saveErr := h.Repo.SavePasswordResetToken(
		user.ID,
		hashResetToken(resetToken),
		expiry,
	)
	assert.NoError(t, saveErr)

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
	assert.Contains(t, rec.Body.String(), "Invalid or expired reset token")
}

func createExpiredToken(t *testing.T, email, secret string) string {
	t.Helper()

	now := time.Now()

	claims := jwt.MapClaims{
		"sub":        email,
		"iss":        tokenutil.TokenIssuer,
		"token_type": tokenutil.TokenTypeReset,
		"iat":        now.Add(-20 * time.Minute).Unix(),
		"exp":        now.Add(-10 * time.Minute).Unix(),
		"jti":        "expired-test-token",
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
	user, lookupErr := h.Repo.GetUserByEmail("testuser@example.com")
	assert.NoError(t, lookupErr)
	assert.NotNil(t, user)

	saveErr := h.Repo.SavePasswordResetToken(
		user.ID,
		hashResetToken(expiredToken),
		time.Now().Add(-1*time.Minute),
	)
	assert.NoError(t, saveErr)

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
	assert.Contains(t, rec.Body.String(), "Invalid or expired reset token")
}

func TestResetPassword_MismatchedToken(t *testing.T) {
	e, h := setup(t)

	// Save valid token in DB
	validToken := generateResetToken(t, "testuser@example.com", h.Cfg)
	user, lookupErr := h.Repo.GetUserByEmail("testuser@example.com")
	assert.NoError(t, lookupErr)
	assert.NotNil(t, user)

	saveErr := h.Repo.SavePasswordResetToken(
		user.ID,
		hashResetToken(validToken),
		time.Now().Add(15*time.Minute),
	)
	assert.NoError(t, saveErr)
	// Use a different (mismatched) token
	wrongToken := generateResetToken(t, "testuser@example.com", h.Cfg)

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
	token := generateResetToken(t, "nonexistent@example.com", h.Cfg)

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
func TestConcurrentRefreshToken(t *testing.T) {
	e, h := setup(t)

	sessionID, err := tokenutil.GenerateSessionID()
	if err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}

	oldRefreshToken, err := tokenutil.GenerateRefreshToken(
		1,
		"user",
		1,
		sessionID,
		h.Cfg,
	)
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}

	expiresAt := time.Now().Add(h.Cfg.JWT.RefreshTTL)

	err = h.Repo.CreateSession(1, sessionID, oldRefreshToken, expiresAt)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	const requestCount = 2

	start := make(chan struct{})
	var wg sync.WaitGroup

	statusCodes := make(chan int, requestCount)
	errorsChan := make(chan error, requestCount)

	for i := 0; i < requestCount; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			form := url.Values{}
			form.Add("refresh_token", oldRefreshToken)

			req := httptest.NewRequest(
				http.MethodPost,
				"/refresh-token",
				strings.NewReader(form.Encode()),
			)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			<-start

			if err := h.RefreshToken(c); err != nil {
				errorsChan <- err
				return
			}

			statusCodes <- rec.Code
		}()
	}

	close(start)
	wg.Wait()

	close(statusCodes)
	close(errorsChan)

	for err := range errorsChan {
		t.Errorf("refresh handler returned error: %v", err)
	}

	for status := range statusCodes {
		if status != http.StatusOK && status != http.StatusUnauthorized {
			t.Errorf("unexpected HTTP status: %d", status)
		}
	}

	var session model.UserSession

	err = h.Repo.DB.Where(
		"session_id = ?",
		sessionID,
	).First(&session).Error

	if err != nil {
		t.Fatalf("failed to retrieve session: %v", err)
	}

	assert.NotNil(t, session.RevokedAt,
		"session should be revoked after concurrent refresh requests")
}
