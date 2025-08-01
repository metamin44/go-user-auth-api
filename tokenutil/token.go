package tokenutil

import (
	"time"

	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
)

func GenerateRefreshToken(userID uint, role string, secret string) (string, error) {
	zap.L().Info("Generating refresh token",
		zap.Uint("user_id", userID),
		zap.String("role", role),
	)

	claims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		zap.L().Error("Failed to sign refresh token",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)
		return "", err
	}

	zap.L().Info("Refresh token generated successfully",
		zap.Uint("user_id", userID),
	)

	return signedToken, nil
}

func GenerateAccessToken(userID uint, role string, secret string) (string, error) {
	zap.L().Info("Generating access token",
		zap.Uint("user_id", userID),
		zap.String("role", role),
	)

	claims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		zap.L().Error("Failed to sign access token",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)
		return "", err
	}

	zap.L().Info("Access token generated successfully",
		zap.Uint("user_id", userID),
	)

	return signedToken, nil
}
