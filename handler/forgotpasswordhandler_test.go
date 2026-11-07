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

		req := httptest.NewRequest(
			http.MethodPost,
			"/forgot-password",
			bytes.NewReader(payload),
		)

		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ForgotPassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(
			t,
			rec.Body.String(),
			"If the email exists, a password reset link will be sent.",
		)
	})
	t.Run("Email Not Registered", func(t *testing.T) {
		body := map[string]string{
			"email": "unknown@example.com",
		}

		payload, err := json.Marshal(body)
		assert.NoError(t, err)

		req := httptest.NewRequest(
			http.MethodPost,
			"/forgot-password",
			bytes.NewReader(payload),
		)

		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.ForgotPassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(
			t,
			rec.Body.String(),
			"If the email exists, a password reset link will be sent.",
		)
	})
}
