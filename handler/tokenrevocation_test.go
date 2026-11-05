package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	middle "reg/middleware"
	"reg/tokenutil"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessTokenRevokedAfterPasswordChange(t *testing.T) {
	_, h := setup(t)

	// Get the real test user from database.
	user, err := h.Repo.GetUserByEmail("testuser@example.com")
	require.NoError(t, err)
	require.NotZero(t, user.TokenVersion)

	// Generate an access token using the current token version.
	oldToken, err := tokenutil.GenerateAccessToken(
		user.ID,
		user.Role,
		user.TokenVersion,
		h.Cfg,
	)
	require.NoError(t, err)

	// Create Echo instance with real JWT middleware.
	e := echo.New()

	auth := e.Group("/auth")
	auth.Use(middle.JWTMiddleware(h.Cfg, h.Repo))

	auth.POST("/change-password", h.ChangePassword)
	auth.GET("/profile", h.Profile)

	// Change password using the old access token.
	payload := map[string]string{
		"old_password": "Password123",
		"new_password": "NewPass456",
	}

	body, err := json.Marshal(payload)
	require.NoError(t, err)

	changeReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/change-password",
		bytes.NewReader(body),
	)
	changeReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	changeReq.Header.Set(echo.HeaderAuthorization, "Bearer "+oldToken)

	changeRec := httptest.NewRecorder()

	e.ServeHTTP(changeRec, changeReq)

	require.Equal(t, http.StatusOK, changeRec.Code)

	// Verify that token version was incremented.
	updatedUser, err := h.Repo.GetUserByID(user.ID)
	require.NoError(t, err)

	assert.Equal(
		t,
		user.TokenVersion+1,
		updatedUser.TokenVersion,
	)

	// Try accessing profile with the old token.
	profileReq := httptest.NewRequest(
		http.MethodGet,
		"/auth/profile",
		nil,
	)
	profileReq.Header.Set(echo.HeaderAuthorization, "Bearer "+oldToken)

	profileRec := httptest.NewRecorder()

	e.ServeHTTP(profileRec, profileReq)

	// The old token must be rejected.
	assert.Equal(
		t,
		http.StatusUnauthorized,
		profileRec.Code,
	)
}

func TestRefreshTokenRevokedAfterPasswordChange(t *testing.T) {
	_, h := setup(t)

	// Get the test user from database.
	user, err := h.Repo.GetUserByEmail("testuser@example.com")
	require.NoError(t, err)
	require.NotZero(t, user.TokenVersion)

	// Generate a refresh token using the current token version.

	sessionID, err := tokenutil.GenerateSessionID()
	require.NoError(t, err)

	oldRefreshToken, err := tokenutil.GenerateRefreshToken(
		user.ID,
		user.Role,
		user.TokenVersion,
		sessionID,
		h.Cfg,
	)
	require.NoError(t, err)

	expiresAt := time.Now().Add(h.Cfg.JWT.RefreshTTL)

	err = h.Repo.CreateSession(
		user.ID,
		sessionID,
		oldRefreshToken,
		expiresAt,
	)
	require.NoError(t, err)

	// Change the user's password.
	payload := map[string]string{
		"old_password": "Password123",
		"new_password": "NewPass456",
	}

	body, err := json.Marshal(payload)
	require.NoError(t, err)

	e := echo.New()
	changeReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/change-password",
		bytes.NewReader(body),
	)
	changeReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	changeReq.Header.Set(echo.HeaderAuthorization, "Bearer test-token")

	changeRec := httptest.NewRecorder()
	changeContext := e.NewContext(changeReq, changeRec)
	changeContext.Set("user_id", user.ID)

	err = h.ChangePassword(changeContext)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, changeRec.Code)

	// Verify that token version was incremented.
	updatedUser, err := h.Repo.GetUserByID(user.ID)
	require.NoError(t, err)

	require.Equal(t, user.TokenVersion+1, updatedUser.TokenVersion)

	// Try refreshing with the old refresh token.
	form := url.Values{}
	form.Set("refresh_token", oldRefreshToken)

	refreshReq := httptest.NewRequest(
		http.MethodPost,
		"/refresh",
		strings.NewReader(form.Encode()),
	)
	refreshReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

	refreshRec := httptest.NewRecorder()
	refreshContext := e.NewContext(refreshReq, refreshRec)

	err = h.RefreshToken(refreshContext)
	require.NoError(t, err)

	// The old refresh token must be rejected.
	require.Equal(t, http.StatusUnauthorized, refreshRec.Code)

}
