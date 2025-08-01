package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reg/model"
	"reg/tokenutil"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfile(t *testing.T) {
	e, h := setup(t)

	t.Run("Valid_Profile_Access", func(t *testing.T) {
		// Get the known user
		user, err := h.Repo.GetUserByEmail("testuser@example.com")
		require.NoError(t, err)

		// Generate a valid access token
		token, err := tokenutil.GenerateAccessToken(user.ID, user.Role, h.Cfg.JWT.SignKey)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Build request
		req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Manually inject the user_id into context (simulate middleware behavior)
		c.Set("user_id", user.ID)

		// Call handler
		if assert.NoError(t, h.Profile(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)

			var response model.UserResponse
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Equal(t, user.ID, response.ID)
			assert.Equal(t, user.Name, response.Name)
			assert.Equal(t, user.Email, response.Email)
			assert.Equal(t, user.Phone, response.Phone)
		}
	})

	t.Run("Missing_user_id_in_context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// user_id not set
		err := h.Profile(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
