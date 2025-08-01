package middle

import (
	"net/http"
	"reg/config"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

func GenerateTokens(userID uint, role string, cfg *config.Config) (string, string, error) {
	logger := zap.L() // global logger

	// Create access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(cfg.JWT.AccessTTL).Unix(),
	})

	// Create refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(cfg.JWT.RefreshTTL).Unix(),
	})

	// Sign access token
	at, err := accessToken.SignedString([]byte(cfg.JWT.SignKey))
	if err != nil {
		logger.Error("Failed to sign access token", zap.Error(err), zap.Uint("user_id", userID))
		return "", "", err
	}

	// Sign refresh token
	rt, err := refreshToken.SignedString([]byte(cfg.JWT.RefreshKey))
	if err != nil {
		logger.Error("Failed to sign refresh token", zap.Error(err), zap.Uint("user_id", userID))
		return "", "", err
	}

	logger.Info("✅ Successfully generated tokens",
		zap.Uint("user_id", userID),
		zap.String("role", role),
		zap.Time("access_token_expires", time.Now().Add(cfg.JWT.AccessTTL)),
		zap.Time("refresh_token_expires", time.Now().Add(cfg.JWT.RefreshTTL)),
	)

	return at, rt, nil
}

func JWTMiddleware(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			logger := zap.L() // use global logger

			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				logger.Warn("Missing Authorization header")
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "missing token"})
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				logger.Warn("Invalid token format", zap.String("authHeader", authHeader))
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid token format"})
			}

			tokenStr := parts[1]
			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
				return []byte(cfg.JWT.SignKey), nil
			})

			if err != nil || !token.Valid {
				logger.Warn("Invalid or expired token", zap.Error(err))
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "invalid or expired token",
				})
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				logger.Error("Invalid token claims structure")
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid token claims"})
			}

			userID, ok := claims["user_id"].(float64)
			if !ok {
				logger.Error("Invalid user_id in token", zap.Any("claims", claims))
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid user_id in token"})
			}

			// Success
			logger.Info("✅ Authenticated request",
				zap.Uint("user_id", uint(userID)),
				zap.String("path", c.Request().URL.Path),
			)

			c.Set("user", token) // Set the full token (needed for RequireRole)
			c.Set("user_id", uint(userID))
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
				logger.Warn("❌ Missing or invalid token in RequireRole middleware")
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
			}

			claims, ok := userToken.Claims.(jwt.MapClaims)
			if !ok {
				logger.Error("❌ Invalid claims structure in token")
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid claims")
			}

			roleClaim, ok := claims["role"].(string)
			if !ok {
				logger.Error("❌ Role claim missing or invalid", zap.Any("claims", claims))
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid role claim")
			}

			userID, _ := claims["user_id"].(float64)

			if roleClaim != requiredRole {
				logger.Warn("🚫 Access denied: insufficient role",
					zap.String("required", requiredRole),
					zap.String("actual", roleClaim),
					zap.Uint("user_id", uint(userID)),
					zap.String("path", c.Request().URL.Path),
				)
				return echo.NewHTTPError(http.StatusForbidden, "Access denied: insufficient role")
			}

			logger.Info("✅ Access granted for role-protected route",
				zap.String("role", roleClaim),
				zap.Uint("user_id", uint(userID)),
				zap.String("path", c.Request().URL.Path),
			)

			return next(c)
		}
	}
}
