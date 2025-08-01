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

func TestChangePassword(t *testing.T) {
	e, handler := setup(t)

	token := generateTestJWT(1) // simulate token for user ID 1

	tests := []struct {
		name           string
		payload        map[string]string
		expectedStatus int
	}{
		{
			name: "Valid Change",
			payload: map[string]string{
				"old_password": "Password123",
				"new_password": "NewPass456",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Wrong Old Password",
			payload: map[string]string{
				"old_password": "WrongOldPass",
				"new_password": "NewPass456",
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid Request (short password)",
			payload: map[string]string{
				"old_password": "Password123",
				"new_password": "123",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user_id", uint(1)) // Simulate middleware

			err := handler.ChangePassword(c)
			if assert.NoError(t, err) {
				assert.Equal(t, tc.expectedStatus, rec.Code)
			}
		})
	}
}
