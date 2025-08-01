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
	"golang.org/x/crypto/bcrypt"
)

func hashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

func TestDeleteUser(t *testing.T) {
	e, h := setup(t)

	t.Run("Valid_Delete", func(t *testing.T) {
		// First, insert a temporary user to be deleted
		tempUser := &model.User{
			Name:     "Delete Me",
			Email:    "deleteme@example.com",
			Phone:    "09333333333",
			Password: hashPassword("TempPass123"), // helper function to hash
		}
		err := h.Repo.CreateUser(tempUser)
		require.NoError(t, err)

		// Generate token for the new user
		token, err := tokenutil.GenerateAccessToken(tempUser.ID, tempUser.Role, h.Cfg.JWT.SignKey)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/auth/delete", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", tempUser.ID)

		err = h.DeleteUser(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Equal(t, "user deleted", resp["message"])
	})

	t.Run("Delete_Non_Existent_User", func(t *testing.T) {
		// Use a random user ID that doesn't exist
		nonExistentUserID := uint(99999)

		token, _ := tokenutil.GenerateAccessToken(nonExistentUserID, "user", h.Cfg.JWT.SignKey)

		req := httptest.NewRequest(http.MethodDelete, "/auth/delete", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", nonExistentUserID)

		_ = h.DeleteUser(c)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
