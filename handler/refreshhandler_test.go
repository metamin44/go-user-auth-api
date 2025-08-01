package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestRefreshToken(t *testing.T) {
	e, h := setup(t)

	type responseBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	t.Run("Valid Refresh Token", func(t *testing.T) {
		token, err := generateRefreshToken(1, "user", h.Cfg.JWT.RefreshKey)
		if err != nil {
			t.Fatalf("❌ Failed to generate token: %v", err)
		}

		form := url.Values{}
		form.Add("refresh_token", token)

		req := httptest.NewRequest(http.MethodPost, "/refresh-token", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if assert.NoError(t, h.RefreshToken(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)

			var resp responseBody
			err := json.Unmarshal(rec.Body.Bytes(), &resp)
			assert.NoError(t, err)
			assert.NotEmpty(t, resp.AccessToken)
			assert.NotEmpty(t, resp.RefreshToken)
		}
	})

	t.Run("Missing Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/refresh-token", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h.RefreshToken(c)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "missing refresh token")
	})

	t.Run("Invalid Token Format", func(t *testing.T) {
		form := url.Values{}
		form.Add("refresh_token", "not-a-valid-jwt")

		req := httptest.NewRequest(http.MethodPost, "/refresh-token", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		h.RefreshToken(c)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid refresh token")
	})
}
