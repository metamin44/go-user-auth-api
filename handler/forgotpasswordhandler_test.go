package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestForgotPassword(t *testing.T) {
	e, handler := setup(t)

	e.POST("/forgot-password", handler.ForgotPassword)

	t.Run("Valid Email", func(t *testing.T) {
		body := map[string]string{
			"email": "testuser@example.com",
		}
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", bytes.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ForgotPassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "Failed to send reset email") // Assuming you log/return the token
	})

	t.Run("User Not Found", func(t *testing.T) {
		body := map[string]string{
			"email": "nonexistent@example.com",
		}
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", bytes.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ForgotPassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, rec.Body.String(), "User not found")
	})
}
