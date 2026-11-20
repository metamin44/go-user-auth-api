//go:build integration

package handler

import (
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

// createSessionForTest creates an active session and returns its access and
// refresh tokens, following the same flow as Login.
func createSessionForTest(t *testing.T, h *UserHandler, userID uint, role string, tokenVersion uint64) (string, string, string) {
	t.Helper()

	sessionID, err := tokenutil.GenerateSessionID()
	require.NoError(t, err)

	refreshToken, err := tokenutil.GenerateRefreshToken(userID, role, tokenVersion, sessionID, h.Cfg)
	require.NoError(t, err)

	err = h.Repo.CreateSession(userID, sessionID, refreshToken, time.Now().Add(h.Cfg.JWT.RefreshTTL))
	require.NoError(t, err)

	accessToken, err := tokenutil.GenerateAccessTokenWithSession(userID, role, tokenVersion, sessionID, h.Cfg)
	require.NoError(t, err)

	return sessionID, accessToken, refreshToken
}

func TestLogoutRevokesSession(t *testing.T) {
	_, h := setup(t)

	user, err := h.Repo.GetUserByEmail("testuser@example.com")
	require.NoError(t, err)

	_, accessToken, refreshToken := createSessionForTest(t, h, user.ID, user.Role, user.TokenVersion)

	e := echo.New()
	auth := e.Group("/auth")
	auth.Use(middle.JWTMiddleware(h.Cfg, h.Repo))
	auth.POST("/logout", h.Logout)
	auth.GET("/profile", h.Profile)

	// Logout with the session-bound access token.
	logoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logoutReq.Header.Set(echo.HeaderAuthorization, "Bearer "+accessToken)
	logoutRec := httptest.NewRecorder()
	e.ServeHTTP(logoutRec, logoutReq)
	require.Equal(t, http.StatusOK, logoutRec.Code)

	// The same access token must now be rejected.
	profileReq := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	profileReq.Header.Set(echo.HeaderAuthorization, "Bearer "+accessToken)
	profileRec := httptest.NewRecorder()
	e.ServeHTTP(profileRec, profileReq)
	assert.Equal(t, http.StatusUnauthorized, profileRec.Code)

	// The session's refresh token must also be rejected.
	form := url.Values{}
	form.Set("refresh_token", refreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(form.Encode()))
	refreshReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	refreshRec := httptest.NewRecorder()
	refreshCtx := e.NewContext(refreshReq, refreshRec)
	require.NoError(t, h.RefreshToken(refreshCtx))
	assert.Equal(t, http.StatusUnauthorized, refreshRec.Code)

	// Logout is idempotent: revoking an already-revoked session is not an error.
	sessionID, _, _ := createSessionForTest(t, h, user.ID, user.Role, user.TokenVersion)
	require.NoError(t, h.Repo.RevokeSession(user.ID, sessionID))
	require.NoError(t, h.Repo.RevokeSession(user.ID, sessionID))
}

func TestLogoutRequiresSessionContext(t *testing.T) {
	_, h := setup(t)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// user_id present but session_id missing (e.g. middleware bypassed).
	c.Set("user_id", uint(1))

	require.NoError(t, h.Logout(c))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
