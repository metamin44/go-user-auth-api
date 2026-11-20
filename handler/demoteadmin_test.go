//go:build integration

package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	middle "reg/middleware"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func demoteRequest(t *testing.T, e *echo.Echo, accessToken string, targetID uint) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(map[string]uint{"user_id": targetID})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/admin/demote", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+accessToken)

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestDemoteAdmin(t *testing.T) {
	_, h := setup(t)

	// Acting admin: the known test user, promoted and given an active session.
	actor, err := h.Repo.GetUserByEmail("testuser@example.com")
	require.NoError(t, err)
	require.NoError(t, h.Repo.PromoteUserToAdmin(actor.ID))
	actor, err = h.Repo.GetUserByID(actor.ID)
	require.NoError(t, err)

	_, adminToken, _ := createSessionForTest(t, h, actor.ID, actor.Role, actor.TokenVersion)

	// Target: a separate admin user.
	target := insertPromotableUser(t, h, "promoteuser@example.com", "Password123", "admin")

	e := echo.New()
	e.PUT("/admin/demote", h.DemoteAdmin,
		middle.JWTMiddleware(h.Cfg, h.Repo),
		middle.RequireRole("admin"),
	)

	rec := demoteRequest(t, e, adminToken, target.ID)
	require.Equal(t, http.StatusOK, rec.Code)

	updated, err := h.Repo.GetUserByID(target.ID)
	require.NoError(t, err)
	assert.Equal(t, "user", updated.Role)
	assert.Equal(t, target.TokenVersion+1, updated.TokenVersion, "demotion must revoke existing tokens")
}

func TestDemoteAdminRejectsSelfDemotion(t *testing.T) {
	_, h := setup(t)

	actor, err := h.Repo.GetUserByEmail("testuser@example.com")
	require.NoError(t, err)
	require.NoError(t, h.Repo.PromoteUserToAdmin(actor.ID))
	actor, err = h.Repo.GetUserByID(actor.ID)
	require.NoError(t, err)

	_, adminToken, _ := createSessionForTest(t, h, actor.ID, actor.Role, actor.TokenVersion)

	e := echo.New()
	e.PUT("/admin/demote", h.DemoteAdmin,
		middle.JWTMiddleware(h.Cfg, h.Repo),
		middle.RequireRole("admin"),
	)

	rec := demoteRequest(t, e, adminToken, actor.ID)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDemoteAdminRejectsNonAdminTarget(t *testing.T) {
	_, h := setup(t)

	actor, err := h.Repo.GetUserByEmail("testuser@example.com")
	require.NoError(t, err)
	require.NoError(t, h.Repo.PromoteUserToAdmin(actor.ID))
	actor, err = h.Repo.GetUserByID(actor.ID)
	require.NoError(t, err)

	_, adminToken, _ := createSessionForTest(t, h, actor.ID, actor.Role, actor.TokenVersion)

	target := insertPromotableUser(t, h, "promoteuser@example.com", "Password123", "user")

	e := echo.New()
	e.PUT("/admin/demote", h.DemoteAdmin,
		middle.JWTMiddleware(h.Cfg, h.Repo),
		middle.RequireRole("admin"),
	)

	rec := demoteRequest(t, e, adminToken, target.ID)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDemoteAdminForbiddenForRegularUser(t *testing.T) {
	_, h := setup(t)

	user, err := h.Repo.GetUserByEmail("testuser@example.com")
	require.NoError(t, err)

	_, userToken, _ := createSessionForTest(t, h, user.ID, user.Role, user.TokenVersion)

	e := echo.New()
	e.PUT("/admin/demote", h.DemoteAdmin,
		middle.JWTMiddleware(h.Cfg, h.Repo),
		middle.RequireRole("admin"),
	)

	rec := demoteRequest(t, e, userToken, user.ID)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
