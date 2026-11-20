//go:build integration

package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginNormalizesEmail(t *testing.T) {
	_, h := setup(t)

	e := echo.New()
	e.POST("/login", h.Login)

	// The known user was registered with a lowercase email; login must match
	// regardless of case or surrounding whitespace.
	payload := map[string]string{
		"email":    "  TestUser@Example.COM  ",
		"password": "Password123",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "access_token")
}

func TestLoginUnknownEmailRejected(t *testing.T) {
	_, h := setup(t)

	e := echo.New()
	e.POST("/login", h.Login)

	payload := map[string]string{
		"email":    "nobody@example.com",
		"password": "Password123",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// Same status and message as a wrong password: no user enumeration.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "email or password incorrect")
}

func TestChangePasswordDeletedUserReturns404(t *testing.T) {
	_, h := setup(t)

	e := echo.New()

	payload := map[string]string{
		"old_password": "Password123",
		"new_password": "NewPass456",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// A user ID that does not exist (e.g. account deleted mid-session).
	c.Set("user_id", uint(999999))

	require.NoError(t, h.ChangePassword(c))
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "user not found")
}
