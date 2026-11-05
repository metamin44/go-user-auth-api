package middle

import (
	"math"
	"net/http"
	"reg/config"
	"reg/tokenutil"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type TokenUserRepository interface {
	GetTokenVersion(userID uint) (uint64, error)
}

func parsePositiveIntegerClaim(claims jwt.MapClaims, claimName string) (uint64, bool) {
	value, ok := claims[claimName].(float64)
	if !ok {
		return 0, false
	}

	// Reject NaN, infinity, zero, negative, and fractional values.
	if math.IsNaN(value) || math.IsInf(value, 0) ||
		value < 1 || math.Trunc(value) != value {
		return 0, false
	}

	// float64 cannot represent every integer above 2^53 - 1 exactly.
	const maxSafeInteger = 1<<53 - 1
	if value > maxSafeInteger {
		return 0, false
	}

	return uint64(value), true
}

func JWTMiddleware(cfg *config.Config, userRepo TokenUserRepository) echo.MiddlewareFunc {
	if cfg == nil || userRepo == nil {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				logger := zap.L()
				logger.Error("JWT middleware is not properly configured")
				return c.JSON(http.StatusInternalServerError, echo.Map{
					"error": "authentication service unavailable",
				})
			}
		}
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			logger := zap.L() // use global logger

			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				logger.Warn("Missing Authorization header")
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "missing token"})
			}

			parts := strings.Fields(authHeader)
			if len(parts) != 2 || parts[0] != "Bearer" {
				logger.Warn("Invalid token format")
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid token format"})
			}

			tokenStr := parts[1]

			claims, err := tokenutil.ParseToken(
				tokenStr,
				cfg.JWT.SignKey,
				tokenutil.TokenTypeAccess,
			)

			if err != nil {
				logger.Warn("Invalid or expired access token", zap.Error(err))
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "invalid or expired token",
				})
			}

			token := &jwt.Token{
				Claims: claims,
				Valid:  true,
			}
			userIDValue, ok := parsePositiveIntegerClaim(claims, "user_id")
			if !ok || userIDValue > uint64(^uint(0)) {
				logger.Warn("Invalid user_id in access token")
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "invalid user_id in token",
				})
			}

			userID := uint(userIDValue)

			// Read token version from JWT claims.
			tokenVersionValue, ok := parsePositiveIntegerClaim(claims, "token_version")
			if !ok {
				logger.Warn("Invalid token version in access token",
					zap.Uint("user_id", userID),
				)
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "invalid token version",
				})
			}

			// Fetch current token version from database.
			currentVersion, err := userRepo.GetTokenVersion(userID)
			if err != nil {
				logger.Error("Failed to retrieve token version",
					zap.Uint("user_id", userID),
					zap.Error(err),
				)
				return c.JSON(http.StatusInternalServerError, echo.Map{
					"error": "authentication service unavailable",
				})
			}

			// Reject revoked tokens.
			if tokenVersionValue != currentVersion {
				logger.Warn("Access token has been revoked",
					zap.Uint("user_id", userID),
				)
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "token has been revoked",
				})
			}

			// Success
			logger.Info("✅ Authenticated request",
				zap.Uint("user_id", userID),
				zap.String("path", c.Request().URL.Path),
			)

			c.Set("user", token) // Set the full token (needed for RequireRole)
			c.Set("user_id", userID)
			return next(c)
		}
	}
}
func RequireRole(requiredRole string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			logger := zap.L()

			userToken, ok := c.Get("user").(*jwt.Token)
			if !ok || userToken == nil {
				logger.Warn("Missing or invalid token in RequireRole middleware")
				return echo.NewHTTPError(
					http.StatusUnauthorized,
					"Invalid token",
				)
			}

			claims, ok := userToken.Claims.(jwt.MapClaims)
			if !ok {
				logger.Error("Invalid claims structure in token")
				return echo.NewHTTPError(
					http.StatusUnauthorized,
					"Invalid claims",
				)
			}

			userIDValue, ok := parsePositiveIntegerClaim(claims, "user_id")
			if !ok || userIDValue > uint64(^uint(0)) {
				logger.Warn("Missing or invalid user_id in token")
				return echo.NewHTTPError(
					http.StatusUnauthorized,
					"Invalid user ID",
				)
			}

			userID := uint(userIDValue)

			roleClaim, ok := claims["role"].(string)
			if !ok || strings.TrimSpace(roleClaim) == "" {
				logger.Warn(
					"Missing or invalid role claim",
					zap.Uint("user_id", userID),
				)
				return echo.NewHTTPError(
					http.StatusUnauthorized,
					"Invalid role claim",
				)
			}

			if roleClaim != requiredRole {
				logger.Warn(
					"Access denied: insufficient role",
					zap.String("required", requiredRole),
					zap.String("actual", roleClaim),
					zap.Uint("user_id", userID),
					zap.String("path", c.Request().URL.Path),
				)

				return echo.NewHTTPError(
					http.StatusForbidden,
					"Access denied: insufficient role",
				)
			}

			logger.Info(
				"Access granted for role-protected route",
				zap.String("role", roleClaim),
				zap.Uint("user_id", userID),
				zap.String("path", c.Request().URL.Path),
			)

			return next(c)
		}
	}
}
