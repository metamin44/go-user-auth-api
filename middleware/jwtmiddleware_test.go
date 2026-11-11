package middle

import (
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"reg/config"
	"reg/tokenutil"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTokenUserRepository struct {
	tokenVersion  uint64
	err           error
	sessionActive bool
	sessionErr    error
}

func (m *mockTokenUserRepository) GetTokenVersion(userID uint) (uint64, error) {
	return m.tokenVersion, m.err
}

func (m *mockTokenUserRepository) IsSessionActive(userID uint, sessionID string) (bool, error) {
	return m.sessionActive, m.sessionErr
}

func TestJWTMiddleware(t *testing.T) {
	const secret = "test-signing-secret-with-enough-length"

	cfg := &config.Config{
		JWT: config.JWTConfig{
			SignKey:   secret,
			AccessTTL: 15 * time.Minute,
		},
	}

	tests := []struct {
		name              string
		authHeader        string
		repoVersion       uint64
		repoErr           error
		repoSessionActive bool
		repoSessionErr    error
		expectedStatus    int
	}{
		{
			name:              "Valid access token",
			authHeader:        "VALID_TOKEN",
			repoVersion:       1,
			repoSessionActive: true,
			expectedStatus:    http.StatusOK,
		},
		{
			name:           "Missing authorization header",
			authHeader:     "",
			repoVersion:    1,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid bearer format",
			authHeader:     "Basic invalid-token",
			repoVersion:    1,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid access token",
			authHeader:     "Bearer invalid-token",
			repoVersion:    1,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Revoked access token",
			authHeader:     "VALID_TOKEN",
			repoVersion:    2,
			expectedStatus: http.StatusUnauthorized,
		},

		{
			name:              "Revoked session",
			authHeader:        "VALID_TOKEN",
			repoVersion:       1,
			repoSessionActive: false,
			expectedStatus:    http.StatusUnauthorized,
		},
		{
			name:              "Session repository error",
			authHeader:        "VALID_TOKEN",
			repoVersion:       1,
			repoSessionActive: true,
			repoSessionErr:    errors.New("database unavailable"),
			expectedStatus:    http.StatusInternalServerError,
		},
		{
			name:           "Repository error",
			authHeader:     "VALID_TOKEN",
			repoVersion:    1,
			repoErr:        errors.New("database unavailable"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockTokenUserRepository{
				tokenVersion:  tt.repoVersion,
				err:           tt.repoErr,
				sessionActive: tt.repoSessionActive,
				sessionErr:    tt.repoSessionErr,
			}

			authHeader := tt.authHeader

			if authHeader == "VALID_TOKEN" {
				token, err := tokenutil.GenerateAccessTokenWithSession(
					1,
					"user",
					1,
					"test-session",
					cfg,
				)
				require.NoError(t, err)
				authHeader = "Bearer " + token
			}

			e := echo.New()

			handler := JWTMiddleware(cfg, repo)(func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if authHeader != "" {
				req.Header.Set(echo.HeaderAuthorization, authHeader)
			}

			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			err := handler(ctx)

			if err != nil {
				e.HTTPErrorHandler(err, ctx)
			}

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				assert.Equal(t, uint(1), ctx.Get("user_id"))
				assert.NotNil(t, ctx.Get("user"))
			}
		})
	}
}

func TestRequireRole(t *testing.T) {
	tests := []struct {
		name           string
		role           string
		requiredRole   string
		expectedStatus int
		missingToken   bool
		missingRole    bool
		invalidUserID  bool
		emptyRole      bool
	}{
		{
			name:           "Admin has access",
			role:           "admin",
			requiredRole:   "admin",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "User cannot access admin route",
			role:           "user",
			requiredRole:   "admin",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Missing user token",
			requiredRole:   "admin",
			expectedStatus: http.StatusUnauthorized,
			missingToken:   true,
		},
		{
			name:           "Missing role claim",
			requiredRole:   "admin",
			expectedStatus: http.StatusUnauthorized,
			missingRole:    true,
		},
		{
			name:           "Invalid user_id",
			role:           "admin",
			requiredRole:   "admin",
			expectedStatus: http.StatusUnauthorized,
			invalidUserID:  true,
		},
		{
			name:           "Empty role",
			role:           "",
			requiredRole:   "admin",
			expectedStatus: http.StatusUnauthorized,
			emptyRole:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()

			handler := RequireRole(tt.requiredRole)(
				func(c echo.Context) error {
					return c.NoContent(http.StatusOK)
				},
			)

			req := httptest.NewRequest(http.MethodGet, "/admin", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			// Set user token in context when available.
			if !tt.missingToken {
				userID := interface{}(float64(1))

				if tt.invalidUserID {
					userID = "abc"
				}

				claims := jwt.MapClaims{
					"user_id": userID,
				}

				if !tt.missingRole {
					claims["role"] = tt.role
				}

				if tt.emptyRole {
					claims["role"] = ""
				}

				ctx.Set("user", &jwt.Token{
					Claims: claims,
					Valid:  true,
				})
			}

			err := handler(ctx)

			if err != nil {
				e.HTTPErrorHandler(err, ctx)
			}

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestJWTMiddlewareInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		repo TokenUserRepository
	}{
		{
			name: "Nil config",
			cfg:  nil,
			repo: &mockTokenUserRepository{tokenVersion: 1},
		},
		{
			name: "Nil repository",
			cfg: &config.Config{
				JWT: config.JWTConfig{
					SignKey:   "test-secret",
					AccessTTL: 15 * time.Minute,
				},
			},
			repo: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()

			handler := JWTMiddleware(tt.cfg, tt.repo)(
				func(c echo.Context) error {
					return c.NoContent(http.StatusOK)
				},
			)

			req := httptest.NewRequest(
				http.MethodGet,
				"/protected",
				nil,
			)
			req.Header.Set(echo.HeaderAuthorization, "Bearer test-token")

			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			err := handler(ctx)

			if err != nil {
				e.HTTPErrorHandler(err, ctx)
			}

			assert.Equal(t, http.StatusInternalServerError, rec.Code)
		})
	}
}
func TestParsePositiveIntegerClaim(t *testing.T) {
	tests := []struct {
		name   string
		value  interface{}
		want   uint64
		wantOK bool
	}{
		{
			name:   "Valid positive integer",
			value:  float64(1),
			want:   1,
			wantOK: true,
		},
		{
			name:   "Zero",
			value:  float64(0),
			wantOK: false,
		},
		{
			name:   "Negative number",
			value:  float64(-1),
			wantOK: false,
		},
		{
			name:   "Fractional number",
			value:  float64(1.5),
			wantOK: false,
		},
		{
			name:   "String instead of number",
			value:  "123",
			wantOK: false,
		},
		{
			name:   "NaN",
			value:  math.NaN(),
			wantOK: false,
		},
		{
			name:   "Positive infinity",
			value:  math.Inf(1),
			wantOK: false,
		},
		{
			name:   "Integer above safe float64 range",
			value:  float64(1 << 53),
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"user_id": tt.value,
			}

			got, ok := tokenutil.ParsePositiveIntegerClaim(claims, "user_id")

			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}
