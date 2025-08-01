package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPromoteToAdmin_Success(t *testing.T) {
	e, h := setup(t)

	user := insertPromotableUser(t, h, "promoteuser@example.com", "password123", "user")

	body := map[string]interface{}{
		"user_id": user.ID,
	}

	reqBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/admin/promote", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.PromoteToAdmin(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "user promoted to admin successfully")
}
