package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setValidEnv establishes a minimal secure configuration; individual tests
// override one variable at a time to verify fail-fast validation.
func setValidEnv(t *testing.T) {
	t.Helper()

	t.Setenv("APP_PORT", "8082")
	t.Setenv("DB_USER", "user")
	t.Setenv("DB_PASS", "test-db-password")
	t.Setenv("DB_HOST", "127.0.0.1")
	t.Setenv("DB_PORT", "3306")
	t.Setenv("DB_NAME", "userdb")
	t.Setenv("JWT_SIGN_KEY", strings.Repeat("s", 32))
	t.Setenv("JWT_REFRESH_KEY", strings.Repeat("r", 32))
	t.Setenv("JWT_RESET_KEY", strings.Repeat("x", 32))
	t.Setenv("ENABLE_EMAIL", "false")
	t.Setenv("ENABLE_SWAGGER", "")
	t.Setenv("CORS_ALLOWED_ORIGINS", "")
	t.Setenv("JWT_ACCESS_TTL", "")
	t.Setenv("JWT_REFRESH_TTL", "")
	t.Setenv("RATE_LIMIT_REGISTER", "")
	t.Setenv("RATE_LIMIT_LOGIN", "")
	t.Setenv("RATE_LIMIT_FORGOT_PASSWORD", "")
	t.Setenv("RATE_LIMIT_REFRESH", "")
	t.Setenv("RATE_LIMIT_RESET_PASSWORD", "")
}

func TestLoadConfigValidDefaults(t *testing.T) {
	setValidEnv(t)

	cfg, err := LoadConfig()
	require.NoError(t, err)

	// Secure defaults apply when optional variables are unset.
	assert.Equal(t, 15*time.Minute, cfg.JWT.AccessTTL)
	assert.Equal(t, 168*time.Hour, cfg.JWT.RefreshTTL)
	assert.Equal(t, "3-M", cfg.RateLimit.Register)
	assert.Equal(t, "5-M", cfg.RateLimit.Login)
	assert.Equal(t, "2-M", cfg.RateLimit.ForgotPassword)
	assert.False(t, cfg.EnableSwagger)
	assert.Empty(t, cfg.CORSAllowedOrigins)
}

func TestLoadConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		envKey string
		envVal string
	}{
		{"Short signing key", "JWT_SIGN_KEY", "too-short"},
		{"Short refresh key", "JWT_REFRESH_KEY", "too-short"},
		{"Short reset key", "JWT_RESET_KEY", "too-short"},
		{"Missing DB user", "DB_USER", ""},
		{"Missing DB password", "DB_PASS", ""},
		{"Missing DB host", "DB_HOST", ""},
		{"Missing DB name", "DB_NAME", ""},
		{"Invalid DB port", "DB_PORT", "not-a-port"},
		{"Invalid app port", "APP_PORT", "99999"},
		{"Invalid access TTL", "JWT_ACCESS_TTL", "abc"},
		{"Negative access TTL", "JWT_ACCESS_TTL", "-5m"},
		{"Access TTL exceeds refresh TTL", "JWT_ACCESS_TTL", "200h"},
		{"Invalid rate limit format", "RATE_LIMIT_LOGIN", "banana"},
		{"Wildcard CORS origin", "CORS_ALLOWED_ORIGINS", "*"},
		{"CORS origin without scheme", "CORS_ALLOWED_ORIGINS", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv(tt.envKey, tt.envVal)

			_, err := LoadConfig()
			assert.Error(t, err)
		})
	}
}

func TestLoadConfigEmailValidation(t *testing.T) {
	setValidEnv(t)
	t.Setenv("ENABLE_EMAIL", "true")
	t.Setenv("EMAIL_HOST", "")

	_, err := LoadConfig()
	assert.Error(t, err, "enabled email with incomplete configuration must fail fast")
}

func TestLoadConfigCORSWhitelist(t *testing.T) {
	setValidEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com, http://localhost:3000")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.com", "http://localhost:3000"}, cfg.CORSAllowedOrigins)
}

func TestLoadConfigCustomTTLsAndSwagger(t *testing.T) {
	setValidEnv(t)
	t.Setenv("JWT_ACCESS_TTL", "30m")
	t.Setenv("JWT_REFRESH_TTL", "72h")
	t.Setenv("ENABLE_SWAGGER", "true")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Minute, cfg.JWT.AccessTTL)
	assert.Equal(t, 72*time.Hour, cfg.JWT.RefreshTTL)
	assert.True(t, cfg.EnableSwagger)
}
