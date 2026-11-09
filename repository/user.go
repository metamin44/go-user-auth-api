package repository

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reg/config"
	"reg/model"
	"strings"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserRepo struct {
	DB     *gorm.DB
	Logger *zap.Logger
}

var (
	ErrEmailAlreadyExists         = errors.New("email already exists")
	ErrPhoneAlreadyExists         = errors.New("phone already exists")
	ErrDuplicateEntry             = errors.New("duplicate entry")
	ErrSessionNotFound            = errors.New("session not found")
	ErrSessionRevoked             = errors.New("session has been revoked")
	ErrSessionExpired             = errors.New("session has expired")
	ErrRefreshTokenReuse          = errors.New("refresh token reuse detected")
	ErrInvalidOrExpiredResetToken = errors.New("invalid or expired reset token")
)

func (r *UserRepo) Ping(ctx context.Context) error {
	if r == nil || r.DB == nil {
		return errors.New("database connection is not initialized")
	}

	sqlDB, err := r.DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.PingContext(ctx)
}

func NewUserRepo(cfg *config.Config) (*UserRepo, error) {
	logger := zap.L()

	dsn := cfg.DSN()

	const maxRetries = 5
	const retryDelay = 2 * time.Second

	const maxOpenConns = 10
	const maxIdleConns = 5
	const connMaxLifetime = 5 * time.Minute
	const connMaxIdleTime = 1 * time.Minute

	var db *gorm.DB
	var err error

	for i := 1; i <= maxRetries; i++ {
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})

		if err == nil {
			var sqlDB *sql.DB

			sqlDB, err = db.DB()

			if err == nil {
				sqlDB.SetMaxOpenConns(maxOpenConns)
				sqlDB.SetMaxIdleConns(maxIdleConns)
				sqlDB.SetConnMaxLifetime(connMaxLifetime)
				sqlDB.SetConnMaxIdleTime(connMaxIdleTime)

				if pingErr := sqlDB.Ping(); pingErr != nil {
					err = pingErr
					_ = sqlDB.Close()
					db = nil
				} else {
					logger.Info("Connected to MySQL with GORM")
					break
				}
			}
		}

		logger.Warn("Database connection attempt failed",
			zap.Int("attempt", i),
			zap.Error(err),
		)

		if i < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	if err != nil {
		return nil, fmt.Errorf(
			"could not connect to database after %d attempts: %w",
			maxRetries,
			err,
		)
	}

	if os.Getenv("RUN_MIGRATION") == "true" {
		logger.Info("Running auto migration for User model")

		if err := db.AutoMigrate(
			&model.User{},
			&model.UserSession{},
		); err != nil {
			sqlDB, dbErr := db.DB()
			if dbErr == nil {
				_ = sqlDB.Close()
			}

			return nil, fmt.Errorf("auto migration failed: %w", err)
		}

		logger.Info("AutoMigration completed successfully")
	}

	return &UserRepo{
		DB:     db,
		Logger: logger,
	}, nil
}

// Close closes the underlying database connection.
func (r *UserRepo) Close() error {
	if r == nil || r.DB == nil {
		return nil
	}

	sqlDB, err := r.DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.Close()
}

func (r *UserRepo) CreateUser(user *model.User) error {
	err := r.DB.Create(user).Error
	if err != nil {
		var mysqlErr *mysqlDriver.MySQLError

		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			switch {
			case strings.Contains(mysqlErr.Message, "uni_users_email"):
				r.Logger.Warn(
					"Duplicate email detected",
					zap.String("email", user.Email),
				)
				return ErrEmailAlreadyExists

			case strings.Contains(mysqlErr.Message, "uni_users_phone"):
				r.Logger.Warn(
					"Duplicate phone detected",
					zap.String("phone", user.Phone),
				)
				return ErrPhoneAlreadyExists

			default:
				return ErrDuplicateEntry
			}
		}

		r.Logger.Error("Failed to create user", zap.Error(err))
		return err
	}

	r.Logger.Info(
		"User created successfully",
		zap.Uint("user_id", user.ID),
	)

	return nil
}

func (r *UserRepo) GetUserByEmail(email string) (*model.User, error) {
	var user model.User

	err := r.DB.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			r.Logger.Warn("User not found by email", zap.String("email", email))
		} else {
			r.Logger.Error("Failed to get user by email", zap.String("email", email), zap.Error(err))
		}
		return nil, err
	}

	r.Logger.Info("User found by email", zap.String("email", email), zap.Uint("user_id", user.ID))
	return &user, nil
}

func (r *UserRepo) GetUserByID(id uint) (*model.User, error) {
	var user model.User

	err := r.DB.First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			r.Logger.Warn("User not found by ID", zap.Uint("user_id", id))
		} else {
			r.Logger.Error("Failed to get user by ID", zap.Uint("user_id", id), zap.Error(err))
		}
		return nil, err
	}

	r.Logger.Info("User found by ID", zap.Uint("user_id", user.ID), zap.String("email", user.Email))
	return &user, nil
}

// UpdateUserProfile updates the user's name and phone.
func (r *UserRepo) UpdateUserProfile(
	id uint,
	name string,
	phone string,
) error {
	if id == 0 {
		return errors.New("user ID is required")
	}

	result := r.DB.Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"name":  name,
			"phone": phone,
		})

	if result.Error != nil {
		var mysqlErr *mysqlDriver.MySQLError

		if errors.As(result.Error, &mysqlErr) && mysqlErr.Number == 1062 {
			switch {
			case strings.Contains(mysqlErr.Message, "uni_users_phone"):
				r.Logger.Warn(
					"Duplicate phone detected during profile update",
					zap.Uint("user_id", id),
				)
				return ErrPhoneAlreadyExists

			default:
				return ErrDuplicateEntry
			}
		}

		r.Logger.Error(
			"Failed to update user profile",
			zap.Uint("user_id", id),
			zap.Error(result.Error),
		)
		return result.Error
	}

	if result.RowsAffected == 0 {
		var existingUser model.User

		err := r.DB.Select("id").First(&existingUser, id).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return gorm.ErrRecordNotFound
			}
			return err
		}
	}

	r.Logger.Info(
		"User profile updated successfully",
		zap.Uint("user_id", id),
	)

	return nil
}

// DeleteUser deletes a user by ID.
func (r *UserRepo) DeleteUser(id uint) error {
	if id == 0 {
		return errors.New("user ID is required")
	}

	result := r.DB.Delete(&model.User{}, id)

	if result.Error != nil {
		r.Logger.Error(
			"Failed to delete user",
			zap.Uint("user_id", id),
			zap.Error(result.Error),
		)
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	r.Logger.Info(
		"User deleted successfully",
		zap.Uint("user_id", id),
	)

	return nil
}

// SavePasswordResetToken stores the hashed reset token and its expiration.
func (r *UserRepo) SavePasswordResetToken(
	id uint,
	hashedToken string,
	expiresAt time.Time,
) error {
	if id == 0 {
		return errors.New("user ID is required")
	}

	if hashedToken == "" {
		return errors.New("hashed reset token is required")
	}

	result := r.DB.Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"reset_token":        hashedToken,
			"reset_token_expiry": expiresAt,
		})

	if result.Error != nil {
		r.Logger.Error(
			"Failed to save password reset token",
			zap.Uint("user_id", id),
			zap.Error(result.Error),
		)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	r.Logger.Info(
		"Password reset token saved",
		zap.Uint("user_id", id),
	)

	return nil
}

func (r *UserRepo) UpdatePassword(id uint, hashedPassword string) error {
	result := r.DB.Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"password":           hashedPassword,
			"token_version":      gorm.Expr("token_version + 1"),
			"reset_token":        nil,
			"reset_token_expiry": nil,
		})

	if result.Error != nil {
		r.Logger.Error("Failed to update password",
			zap.Uint("user_id", id),
			zap.Error(result.Error),
		)
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	r.Logger.Info("Password updated, existing tokens revoked, and reset token cleared",
		zap.Uint("user_id", id),
	)

	return nil
}

// CompletePasswordReset atomically validates and consumes the reset token,
// updates the password, and revokes all existing access and refresh tokens.
func (r *UserRepo) CompletePasswordReset(
	id uint,
	hashedPassword string,
	hashedResetToken string,
	now time.Time,
) error {
	result := r.DB.Model(&model.User{}).
		Where(
			"id = ? AND reset_token = ? AND reset_token_expiry > ?",
			id,
			hashedResetToken,
			now,
		).
		Updates(map[string]interface{}{
			"password":           hashedPassword,
			"reset_token":        nil,
			"reset_token_expiry": nil,
			"token_version":      gorm.Expr("token_version + 1"),
		})

	if result.Error != nil {
		r.Logger.Error(
			"Failed to complete password reset",
			zap.Uint("user_id", id),
			zap.Error(result.Error),
		)
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrInvalidOrExpiredResetToken
	}

	r.Logger.Info(
		"Password reset completed and existing tokens revoked",
		zap.Uint("user_id", id),
	)

	return nil
}

func (r *UserRepo) PromoteUserToAdmin(userID uint) error {
	result := r.DB.Model(&model.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"role":          "admin",
			"token_version": gorm.Expr("token_version + 1"),
		})

	if result.Error != nil {
		r.Logger.Error(
			"Failed to promote user to admin",
			zap.Uint("user_id", userID),
			zap.Error(result.Error),
		)
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	r.Logger.Info(
		"User promoted to admin and existing tokens revoked",
		zap.Uint("user_id", userID),
	)

	return nil
}

// GetTokenVersion returns the current token version of a user.
func (r *UserRepo) GetTokenVersion(userID uint) (uint64, error) {
	var user model.User

	err := r.DB.
		Select("token_version").
		First(&user, userID).Error

	if err != nil {
		return 0, err
	}

	return user.TokenVersion, nil
}

func hashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (r *UserRepo) CreateSession(
	userID uint,
	sessionID string,
	refreshToken string,
	expiresAt time.Time,
) error {
	if userID == 0 {
		return errors.New("user ID is required")
	}

	if sessionID == "" || refreshToken == "" {
		return errors.New("session ID and refresh token are required")
	}

	if !expiresAt.After(time.Now()) {
		return errors.New("session expiration must be in the future")
	}

	session := model.UserSession{
		UserID:           userID,
		SessionID:        sessionID,
		RefreshTokenHash: hashRefreshToken(refreshToken),
		ExpiresAt:        expiresAt,
	}

	if err := r.DB.Create(&session).Error; err != nil {
		r.Logger.Error(
			"Failed to create user session",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)
		return err
	}

	r.Logger.Info(
		"User session created",
		zap.Uint("user_id", userID),
	)

	return nil
}

func (r *UserRepo) RotateSession(

	userID uint,
	sessionID string,
	oldRefreshToken string,
	newRefreshToken string,
	newExpiresAt time.Time,
) error {
	if userID == 0 || sessionID == "" ||
		oldRefreshToken == "" || newRefreshToken == "" {
		return errors.New("invalid session rotation parameters")
	}

	if !newExpiresAt.After(time.Now()) {
		return errors.New("new session expiration must be in the future")
	}
	oldHash := hashRefreshToken(oldRefreshToken)
	newHash := hashRefreshToken(newRefreshToken)

	var tokenReuseDetected bool

	err := r.DB.Transaction(func(tx *gorm.DB) error {
		var session model.UserSession

		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where(
				"user_id = ? AND session_id = ?",
				userID,
				sessionID,
			).
			First(&session).Error

		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}

		if err != nil {
			return err
		}

		if session.RevokedAt != nil {
			return ErrSessionRevoked
		}

		if !session.ExpiresAt.After(time.Now()) {
			return ErrSessionExpired
		}

		// Detect reuse of an already rotated refresh token.
		if subtle.ConstantTimeCompare(
			[]byte(session.RefreshTokenHash),
			[]byte(oldHash),
		) != 1 {
			now := time.Now()

			result := tx.Model(&session).
				Update("revoked_at", &now)

			if result.Error != nil {
				return result.Error
			}

			if result.RowsAffected == 0 {
				return ErrSessionNotFound
			}

			tokenReuseDetected = true

			// Return nil so the transaction commits the revocation.
			return nil
		}

		now := time.Now()

		result := tx.Model(&session).Updates(map[string]interface{}{
			"refresh_token_hash": newHash,
			"expires_at":         newExpiresAt,
			"last_used_at":       &now,
		})

		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected == 0 {
			return ErrSessionNotFound
		}

		return nil
	})

	if err != nil {
		return err
	}

	if tokenReuseDetected {
		return ErrRefreshTokenReuse
	}

	return nil
}
