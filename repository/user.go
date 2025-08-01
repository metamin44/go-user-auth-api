package repository

import (
	"errors"
	"fmt"
	"os"
	"reg/config"
	"reg/model"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type UserRepo struct {
	DB     *gorm.DB
	Logger *zap.Logger
}

func NewUserRepo(cfg *config.Config) (*UserRepo, error) {
	var db *gorm.DB
	var err error

	logger := zap.L() // get the global Zap logger (make sure it's initialized in main)
	logger.Info("Hello from UserRepo constructor -test log")

	dsn := cfg.DSN()

	// Retry logic: try to connect up to 10 times with 3s delay
	for i := 1; i <= 10; i++ {
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err == nil {
			sqlDB, _ := db.DB()
			if pingErr := sqlDB.Ping(); pingErr == nil {
				logger.Info("✅ Connected to MySQL with GORM")
				break
			} else {
				err = pingErr
			}
		}

		logger.Warn("⏳ Attempt to connect to DB failed",
			zap.Int("attempt", i),
			zap.Error(err),
		)
		time.Sleep(3 * time.Second)
	}

	if err != nil {
		logger.Error("❌ Could not connect to DB after retries", zap.Error(err))
		return nil, fmt.Errorf("❌ could not connect to database after retries: %w", err)
	}

	// Auto-migrate User model
	if os.Getenv("RUN_MIGRATION") == "true" {
		logger.Info("Running auto migration for User model...")
		if err := db.AutoMigrate(&model.User{}); err != nil {
			logger.Fatal("❌ AutoMigration failed", zap.Error(err))
		} else {
			logger.Info("✅ AutoMigration completed successfully")
		}
	}

	return &UserRepo{DB: db, Logger: logger}, nil
}

func (r *UserRepo) CreateUser(user *model.User) error {
	err := r.DB.Create(user).Error
	if err != nil {
		r.Logger.Error("❌ Failed to create user", zap.Error(err))

		// Inspect raw error string
		rawErr := err.Error()
		if strings.Contains(rawErr, "Duplicate entry") {
			if strings.Contains(rawErr, "uni_users_email") {
				r.Logger.Warn("⚠️ Duplicate email detected", zap.String("email", user.Email))
				return fmt.Errorf("email already exists")
			}
			if strings.Contains(rawErr, "uni_users_phone") {
				r.Logger.Warn("⚠️ Duplicate phone detected", zap.String("phone", user.Phone))
				return fmt.Errorf("phone already exists")
			}
			return fmt.Errorf("duplicate entry")
		}

		return err
	}

	r.Logger.Info("✅ User created successfully", zap.Uint("user_id", user.ID), zap.String("email", user.Email))
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

func (r *UserRepo) UpdateUser(id uint, updates map[string]interface{}) error {
	err := r.DB.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error
	if err != nil {
		r.Logger.Error("Failed to update user", zap.Uint("user_id", id), zap.Any("updates", updates), zap.Error(err))
		return err
	}

	r.Logger.Info("User updated successfully", zap.Uint("user_id", id), zap.Any("updates", updates))
	return nil
}

func (r *UserRepo) DeleteUser(id uint) error {
	err := r.DB.Delete(&model.User{}, id).Error
	if err != nil {
		r.Logger.Error("Failed to delete user", zap.Uint("user_id", id), zap.Error(err))
		return err
	}

	r.Logger.Info("User deleted successfully", zap.Uint("user_id", id))
	return nil
}

func (r *UserRepo) UpdatePassword(id uint, hashedPassword string) error {
	err := r.DB.Model(&model.User{}).Where("id = ?", id).Update("password", hashedPassword).Error
	if err != nil {
		r.Logger.Error("Failed to update password", zap.Uint("user_id", id), zap.Error(err))
		return err
	}

	r.Logger.Info("Password updated successfully", zap.Uint("user_id", id))
	return nil
}

func (r *UserRepo) PromoteUserToAdmin(userID uint) error {
	err := r.DB.Model(&model.User{}).Where("id = ?", userID).Update("role", "admin").Error
	if err != nil {
		r.Logger.Error("Failed to promote user to admin", zap.Uint("user_id", userID), zap.Error(err))
		return err
	}

	r.Logger.Info("User promoted to admin", zap.Uint("user_id", userID))
	return nil
}
