package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestAdminDashboard_AccessGranted(t *testing.T) {

	e, h := setup(t)

	token := generateAdminTestJWT("admin", h.Cfg.JWT.SignKey)

	req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Simulate JWT middleware behavior
	parsed, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(h.Cfg.JWT.SignKey), nil
	})
	c.Set("user", parsed)

	if assert.NoError(t, h.AdminDashboard(c)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Welcome Admin")
	}
}

func TestAdminDashboard_AccessDenied_UserRole(t *testing.T) {
	e, h := setup(t)

	token := generateAdminTestJWT("user", h.Cfg.JWT.SignKey)

	req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Simulate JWT middleware behavior
	parsed, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(h.Cfg.JWT.SignKey), nil
	})
	c.Set("user", parsed)

	if assert.NoError(t, h.AdminDashboard(c)) {
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "Admins only")
	}
}

func TestAdminDashboard_Unauthorized(t *testing.T) {
	e, h := setup(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Simulate missing JWT middleware
	c.Set("user", nil)

	if assert.NoError(t, h.AdminDashboard(c)) {
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "Unauthorized")
	}
}
