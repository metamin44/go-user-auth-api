package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestLogin(t *testing.T) {
	e, h := setup(t)

	tests := []struct {
		name           string
		payload        map[string]string
		expectedStatus int
		expectedField  string
		expectNonEmpty bool
		expectedValue  string
	}{
		{
			name: "Valid Login",
			payload: map[string]string{
				"email":    "testuser@example.com",
				"password": "Password123", // change to actual password if hashing check is used
			},
			expectedStatus: http.StatusOK,
			expectedField:  "access_token",
			expectNonEmpty: true,
		},
		{
			name: "Invalid Email",
			payload: map[string]string{
				"email":    "wrong@example.com",
				"password": "Password123",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedField:  "error",
			expectedValue:  "email or password incorrect",
		},
		{
			name: "Wrong Password",
			payload: map[string]string{
				"email":    "testuser@example.com",
				"password": "WrongPass123",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedField:  "error",
			expectedValue:  "email or password incorrect",
		},
		{
			name: "Missing Email",
			payload: map[string]string{
				"password": "Password123",
			},
			expectedStatus: http.StatusBadRequest,
			expectedField:  "error",
			expectedValue:  "cannot be blank",
		},
		{
			name: "Missing Password",
			payload: map[string]string{
				"email": "testuser@example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectedField:  "error",
			expectedValue:  "cannot be blank",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			c := e.NewContext(req, rec)

			if assert.NoError(t, h.Login(c)) {
				assert.Equal(t, tc.expectedStatus, rec.Code)

				var resp map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				assert.NoError(t, err)

				val, exists := resp[tc.expectedField]
				assert.True(t, exists, fmt.Sprintf("Expected field '%s' not found", tc.expectedField))

				if tc.expectNonEmpty {
					assert.NotEmpty(t, val, "Expected a non-empty token")
				} else {
					assert.Contains(t, val, tc.expectedValue)
				}
			}
		})
	}
}
