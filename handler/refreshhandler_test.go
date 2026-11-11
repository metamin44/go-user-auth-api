package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	middle "reg/middleware"
	"reg/model"
	"reg/tokenutil"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestRefreshToken(t *testing.T) {
	e, h := setup(t)

	type responseBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	t.Run("Valid Refresh Token And Reuse Detection", func(t *testing.T) {
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

		err = h.Repo.CreateSession(
			1,
			sessionID,
			oldRefreshToken,
			expiresAt,
		)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		// First refresh: should succeed.
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

		if !assert.NoError(t, h.RefreshToken(c)) {
			return
		}

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp responseBody
		err = json.Unmarshal(rec.Body.Bytes(), &resp)

		assert.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.NotEqual(t, oldRefreshToken, resp.RefreshToken)
		// Verify that the newly issued access token is still valid.
		authE := echo.New()
		auth := authE.Group("/auth")
		auth.Use(middle.JWTMiddleware(h.Cfg, h.Repo))
		auth.GET("/profile", h.Profile)

		profileReq := httptest.NewRequest(
			http.MethodGet,
			"/auth/profile",
			nil,
		)
		profileReq.Header.Set(
			echo.HeaderAuthorization,
			"Bearer "+resp.AccessToken,
		)

		profileRec := httptest.NewRecorder()
		authE.ServeHTTP(profileRec, profileReq)

		assert.Equal(t, http.StatusOK, profileRec.Code)

		// Second refresh using the old token: should fail.
		form = url.Values{}
		form.Add("refresh_token", oldRefreshToken)

		req = httptest.NewRequest(
			http.MethodPost,
			"/refresh-token",
			strings.NewReader(form.Encode()),
		)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)

		h.RefreshToken(c)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		// Verify that the session was actually revoked in the database.
		var session model.UserSession

		err = h.Repo.DB.Where(
			"session_id = ?",
			sessionID,
		).First(&session).Error

		assert.NoError(t, err)
		assert.NotNil(t, session.RevokedAt)
		// Verify that the access token from the revoked session is rejected.
		revokedAuthE := echo.New()
		revokedAuth := revokedAuthE.Group("/auth")
		revokedAuth.Use(middle.JWTMiddleware(h.Cfg, h.Repo))
		revokedAuth.GET("/profile", h.Profile)

		revokedProfileReq := httptest.NewRequest(
			http.MethodGet,
			"/auth/profile",
			nil,
		)
		revokedProfileReq.Header.Set(
			echo.HeaderAuthorization,
			"Bearer "+resp.AccessToken,
		)

		revokedProfileRec := httptest.NewRecorder()
		revokedAuthE.ServeHTTP(revokedProfileRec, revokedProfileReq)

		assert.Equal(t, http.StatusUnauthorized, revokedProfileRec.Code)

		// Even the newly issued token should now be rejected.
		form = url.Values{}
		form.Add("refresh_token", resp.RefreshToken)

		req = httptest.NewRequest(
			http.MethodPost,
			"/refresh-token",
			strings.NewReader(form.Encode()),
		)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)

		h.RefreshToken(c)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Expired Session", func(t *testing.T) {
		sessionID, err := tokenutil.GenerateSessionID()
		if err != nil {
			t.Fatalf("failed to generate session ID: %v", err)
		}

		refreshToken, err := tokenutil.GenerateRefreshToken(
			1,
			"user",
			1,
			sessionID,
			h.Cfg,
		)
		if err != nil {
			t.Fatalf("failed to generate refresh token: %v", err)
		}

		// Create a valid session first.
		expiresAt := time.Now().Add(h.Cfg.JWT.RefreshTTL)
		err = h.Repo.CreateSession(1, sessionID, refreshToken, expiresAt)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		// Simulate an expired session directly in the database.
		expiredAt := time.Now().Add(-1 * time.Minute)
		err = h.Repo.DB.Model(&model.UserSession{}).
			Where("session_id = ?", sessionID).
			Update("expires_at", expiredAt).Error
		if err != nil {
			t.Fatalf("failed to expire session: %v", err)
		}

		form := url.Values{}
		form.Add("refresh_token", refreshToken)

		req := httptest.NewRequest(
			http.MethodPost,
			"/refresh-token",
			strings.NewReader(form.Encode()),
		)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h.RefreshToken(c)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "refresh token is invalid, expired, or revoked")
	})

	t.Run("Revoked Session", func(t *testing.T) {
		sessionID, err := tokenutil.GenerateSessionID()
		if err != nil {
			t.Fatalf("failed to generate session ID: %v", err)
		}

		refreshToken, err := tokenutil.GenerateRefreshToken(
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

		err = h.Repo.CreateSession(
			1,
			sessionID,
			refreshToken,
			expiresAt,
		)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		// Revoke the session directly in the database.
		err = h.Repo.DB.Model(&model.UserSession{}).
			Where("session_id = ?", sessionID).
			Update("revoked_at", time.Now()).Error

		if err != nil {
			t.Fatalf("failed to revoke session: %v", err)
		}

		form := url.Values{}
		form.Add("refresh_token", refreshToken)

		req := httptest.NewRequest(
			http.MethodPost,
			"/refresh-token",
			strings.NewReader(form.Encode()),
		)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h.RefreshToken(c)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(
			t,
			rec.Body.String(),
			"refresh token is invalid, expired, or revoked",
		)
	})
}
