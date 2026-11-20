package tokenutil

import (
	"strings"
	"testing"
	"time"

	"reg/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() *config.Config {
	return &config.Config{
		JWT: config.JWTConfig{
			SignKey:    strings.Repeat("s", 32),
			RefreshKey: strings.Repeat("r", 32),
			ResetKey:   strings.Repeat("x", 32),
			AccessTTL:  15 * time.Minute,
			RefreshTTL: 168 * time.Hour,
		},
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	cfg := testConfig()

	token, err := GenerateAccessTokenWithSession(7, "admin", 3, "session-abc", cfg)
	require.NoError(t, err)

	claims, err := ParseToken(token, cfg.JWT.SignKey, TokenTypeAccess)
	require.NoError(t, err)

	assert.Equal(t, float64(7), claims["user_id"])
	assert.Equal(t, "admin", claims["role"])
	assert.Equal(t, float64(3), claims["token_version"])
	assert.Equal(t, "session-abc", claims["session_id"])
	assert.Equal(t, TokenTypeAccess, claims["token_type"])
}

func TestRefreshTokenRoundTrip(t *testing.T) {
	cfg := testConfig()

	token, err := GenerateRefreshToken(7, "user", 1, "session-abc", cfg)
	require.NoError(t, err)

	claims, err := ParseToken(token, cfg.JWT.RefreshKey, TokenTypeRefresh)
	require.NoError(t, err)
	assert.Equal(t, "session-abc", claims["session_id"])
}

func TestResetTokenUsesSharedTTL(t *testing.T) {
	cfg := testConfig()

	token, err := GenerateResetToken("user@example.com", cfg)
	require.NoError(t, err)

	claims, err := ParseToken(token, cfg.JWT.ResetKey, TokenTypeReset)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims["sub"])

	iat, ok := claims["iat"].(float64)
	require.True(t, ok)
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	assert.Equal(t, ResetTokenTTL.Seconds(), exp-iat)
}

func TestParseTokenRejectsWrongType(t *testing.T) {
	cfg := testConfig()

	access, err := GenerateAccessTokenWithSession(1, "user", 1, "s", cfg)
	require.NoError(t, err)

	// An access token must never be accepted as a refresh or reset token.
	_, err = ParseToken(access, cfg.JWT.RefreshKey, TokenTypeRefresh)
	assert.Error(t, err)

	_, err = ParseToken(access, cfg.JWT.ResetKey, TokenTypeReset)
	assert.Error(t, err)
}

func TestParseTokenRejectsWrongKey(t *testing.T) {
	cfg := testConfig()

	token, err := GenerateAccessTokenWithSession(1, "user", 1, "s", cfg)
	require.NoError(t, err)

	_, err = ParseToken(token, strings.Repeat("w", 32), TokenTypeAccess)
	assert.Error(t, err)
}

func TestParseTokenRejectsExpired(t *testing.T) {
	cfg := testConfig()

	claims := jwt.MapClaims{
		"token_type": TokenTypeAccess,
		"iss":        TokenIssuer,
		"iat":        time.Now().Add(-2 * time.Hour).Unix(),
		"exp":        time.Now().Add(-time.Hour).Unix(),
		"user_id":    1,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(cfg.JWT.SignKey))
	require.NoError(t, err)

	_, err = ParseToken(signed, cfg.JWT.SignKey, TokenTypeAccess)
	assert.Error(t, err)
}

func TestParseTokenRejectsTampered(t *testing.T) {
	cfg := testConfig()

	token, err := GenerateAccessTokenWithSession(1, "user", 1, "s", cfg)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	// Flip a character in the signature.
	tampered := parts[0] + "." + parts[1] + "." + "A" + parts[2][1:]

	_, err = ParseToken(tampered, cfg.JWT.SignKey, TokenTypeAccess)
	assert.Error(t, err)
}

func TestParseTokenRejectsNoneAlgorithm(t *testing.T) {
	cfg := testConfig()

	claims := jwt.MapClaims{
		"token_type": TokenTypeAccess,
		"iss":        TokenIssuer,
		"exp":        time.Now().Add(time.Hour).Unix(),
		"user_id":    1,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = ParseToken(signed, cfg.JWT.SignKey, TokenTypeAccess)
	assert.Error(t, err, "alg=none tokens must be rejected")
}

func TestGenerateTokenInputValidation(t *testing.T) {
	cfg := testConfig()

	_, err := GenerateAccessTokenWithSession(1, "user", 1, "", cfg)
	assert.Error(t, err, "empty session ID must be rejected")

	_, err = GenerateRefreshToken(1, "user", 1, "", cfg)
	assert.Error(t, err)

	_, err = GenerateResetToken("", cfg)
	assert.Error(t, err)

	emptyKeyCfg := testConfig()
	emptyKeyCfg.JWT.SignKey = ""
	_, err = GenerateAccessTokenWithSession(1, "user", 1, "s", emptyKeyCfg)
	assert.Error(t, err, "empty signing key must be rejected")
}

func TestParseTokenInputValidation(t *testing.T) {
	cfg := testConfig()

	_, err := ParseToken("", cfg.JWT.SignKey, TokenTypeAccess)
	assert.Error(t, err)

	_, err = ParseToken("token", "", TokenTypeAccess)
	assert.Error(t, err)

	_, err = ParseToken("token", cfg.JWT.SignKey, "")
	assert.Error(t, err)
}
