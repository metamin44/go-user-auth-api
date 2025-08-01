package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reg/model"
	"reg/tokenutil"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateUser(t *testing.T) {
	e, h := setup(t)

	t.Run("Valid_Update", func(t *testing.T) {
		user, err := h.Repo.GetUserByEmail("testuser@example.com")
		require.NoError(t, err)

		// Generate valid token
		token, err := tokenutil.GenerateAccessToken(user.ID, user.Role, h.Cfg.JWT.SignKey)
		require.NoError(t, err)

		// Prepare request payload
		updateBody := model.UpdateUserRequest{
			Name:  "Updated User",
			Phone: "09999999999",
		}
		bodyBytes, _ := json.Marshal(updateBody)

		req := httptest.NewRequest(http.MethodPut, "/auth/update", bytes.NewReader(bodyBytes))
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", user.ID)

		err = h.UpdateUser(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "user updated", response["message"])
	})

	t.Run("Invalid_Request_Body", func(t *testing.T) {
		user, _ := h.Repo.GetUserByEmail("testuser@example.com")
		token, _ := tokenutil.GenerateAccessToken(user.ID, user.Role, h.Cfg.JWT.SignKey)

		req := httptest.NewRequest(http.MethodPut, "/auth/update", strings.NewReader(`invalid-json`))
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", user.ID)

		_ = h.UpdateUser(c)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Validation_Error", func(t *testing.T) {
		user, _ := h.Repo.GetUserByEmail("testuser@example.com")
		token, _ := tokenutil.GenerateAccessToken(user.ID, user.Role, h.Cfg.JWT.SignKey)

		invalidBody := model.UpdateUserRequest{
			Name:  "",    // Name required by validation
			Phone: "123", // Too short
		}
		bodyBytes, _ := json.Marshal(invalidBody)

		req := httptest.NewRequest(http.MethodPut, "/auth/update", bytes.NewReader(bodyBytes))
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", user.ID)

		_ = h.UpdateUser(c)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
