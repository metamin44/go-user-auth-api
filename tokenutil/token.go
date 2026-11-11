package tokenutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"reg/config"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	TokenTypeReset   = "reset"

	TokenIssuer = "go-user-auth-api"
)

// GenerateAccessToken creates a signed access token.
func GenerateAccessToken(
	userID uint,
	role string,
	tokenVersion uint64,
	cfg *config.Config,
) (string, error) {
	return generateToken(
		userID,
		role,
		tokenVersion,
		"",
		"",
		TokenTypeAccess,
		cfg.JWT.SignKey,
		cfg.JWT.AccessTTL,
	)
}

// GenerateAccessTokenWithSession creates an access token linked to a session.
func GenerateAccessTokenWithSession(
	userID uint,
	role string,
	tokenVersion uint64,
	sessionID string,
	cfg *config.Config,
) (string, error) {
	if sessionID == "" {
		return "", errors.New("session ID cannot be empty")
	}

	return generateToken(
		userID,
		role,
		tokenVersion,
		"",
		sessionID,
		TokenTypeAccess,
		cfg.JWT.SignKey,
		cfg.JWT.AccessTTL,
	)
}

// GenerateRefreshToken creates a signed refresh token linked to a session.
func GenerateRefreshToken(
	userID uint,
	role string,
	tokenVersion uint64,
	sessionID string,
	cfg *config.Config,
) (string, error) {
	if sessionID == "" {
		return "", errors.New("session ID cannot be empty")
	}

	return generateToken(
		userID,
		role,
		tokenVersion,
		"",
		sessionID,
		TokenTypeRefresh,
		cfg.JWT.RefreshKey,
		cfg.JWT.RefreshTTL,
	)
}

// GenerateResetToken creates a signed password-reset token.
func GenerateResetToken(email string, cfg *config.Config) (string, error) {
	if email == "" {
		return "", errors.New("email cannot be empty")
	}

	return generateToken(
		0,
		"",
		0,
		email,
		"",
		TokenTypeReset,
		cfg.JWT.ResetKey,
		15*time.Minute,
	)
}

// generateToken creates a JWT with common claims.
func generateToken(
	userID uint,
	role string,
	tokenVersion uint64,
	email string,
	sessionID string,
	tokenType string,
	secret string,
	ttl time.Duration,
) (string, error) {
	if secret == "" {
		return "", errors.New("JWT signing key is empty")
	}

	if ttl <= 0 {
		return "", errors.New("token expiration must be greater than zero")
	}

	now := time.Now()

	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", errors.New("failed to generate token ID")
	}

	jti := hex.EncodeToString(jtiBytes)

	claims := jwt.MapClaims{
		"token_type": tokenType,
		"iss":        TokenIssuer,
		"iat":        now.Unix(),
		"exp":        now.Add(ttl).Unix(),
		"jti":        jti,
	}
	if sessionID != "" {
		claims["session_id"] = sessionID
	}

	if userID > 0 {
		claims["user_id"] = userID
		claims["role"] = role
		claims["token_version"] = tokenVersion
	}

	if email != "" {
		claims["sub"] = email
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))
}

// ParseToken validates a JWT signature, expiration, issuer and token type.
func ParseToken(tokenString string, secret string, expectedType string) (jwt.MapClaims, error) {
	if tokenString == "" {
		return nil, errors.New("token cannot be empty")
	}

	if secret == "" {
		return nil, errors.New("JWT signing key is empty")
	}

	if expectedType == "" {
		return nil, errors.New("expected token type cannot be empty")
	}

	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}

			return []byte(secret), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(TokenIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims["token_type"] != expectedType {
		return nil, errors.New("unexpected token type")
	}

	return claims, nil
}

// GenerateSessionID creates a cryptographically secure session identifier.
func GenerateSessionID() (string, error) {
	sessionBytes := make([]byte, 32)

	if _, err := rand.Read(sessionBytes); err != nil {
		return "", errors.New("failed to generate session ID")
	}

	return hex.EncodeToString(sessionBytes), nil
}
