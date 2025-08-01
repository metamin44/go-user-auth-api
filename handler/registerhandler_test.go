package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	e, handler := setup(t)

	// 1. Test successful registration
	t.Run("Success", func(t *testing.T) {
		reqBody := `{
   "name": "New User",
   "email": "newuser@example.com",
   "phone": "09330000000",
   "password": "StrongPassword123"
  }`
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.Register(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Contains(t, rec.Body.String(), "user registered successfully")
	})

	// 2. Test duplicate email
	t.Run("Duplicate_Email", func(t *testing.T) {
		reqBody := `{
   "name": "Another User",
   "email": "testuser@example.com",
   "phone": "09331111111",
   "password": "StrongPassword123"
  }`
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.Register(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "email already exists")
	})

	// 3. Test duplicate phone
	t.Run("Duplicate_Phone", func(t *testing.T) {
		reqBody := `{
   "name": "Another User",
   "email": "uniqueuser@example.com",
   "phone": "09123456789",
   "password": "StrongPassword123"
  }`
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.Register(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "phone already exists")
	})
}
