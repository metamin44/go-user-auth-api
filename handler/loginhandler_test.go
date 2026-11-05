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

func TestLogin(t *testing.T) {
	e, h := setup(t)

	tests := []struct {
		name            string
		payload         map[string]string
		expectedStatus  int
		expectedMessage string
		expectTokens    bool
	}{
		{
			name: "Valid Login",
			payload: map[string]string{
				"email":    "testuser@example.com",
				"password": "Password123",
			},
			expectedStatus: http.StatusOK,
			expectTokens:   true,
		},
		{
			name: "Invalid Email",
			payload: map[string]string{
				"email":    "wrong@example.com",
				"password": "Password123",
			},
			expectedStatus:  http.StatusUnauthorized,
			expectedMessage: "email or password incorrect",
		},
		{
			name: "Wrong Password",
			payload: map[string]string{
				"email":    "testuser@example.com",
				"password": "WrongPass123",
			},
			expectedStatus:  http.StatusUnauthorized,
			expectedMessage: "email or password incorrect",
		},
		{
			name: "Missing Email",
			payload: map[string]string{
				"password": "Password123",
			},
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: "cannot be blank",
		},
		{
			name: "Missing Password",
			payload: map[string]string{
				"email": "testuser@example.com",
			},
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: "cannot be blank",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.payload)
			assert.NoError(t, err)
			if err != nil {
				return
			}

			req := httptest.NewRequest(
				http.MethodPost,
				"/login",
				bytes.NewReader(body),
			)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if assert.NoError(t, h.Login(c)) {
				assert.Equal(t, tc.expectedStatus, rec.Code)

				var resp struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
					Data    struct {
						AccessToken  string `json:"access_token"`
						RefreshToken string `json:"refresh_token"`
					} `json:"data"`
				}

				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				assert.NoError(t, err)
				if err != nil {
					return
				}

				assert.Equal(t, tc.expectedStatus, resp.Code)

				if tc.expectTokens {
					assert.Equal(t, "Login successful", resp.Message)
					assert.NotEmpty(t, resp.Data.AccessToken,
						"Expected a non-empty access token")
					assert.NotEmpty(t, resp.Data.RefreshToken,
						"Expected a non-empty refresh token")
				} else {
					assert.Contains(t, resp.Message, tc.expectedMessage)
				}
			}
		})
	}
}
