package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
)

type Config struct {
	Database  DatabaseConfig
	JWT       JWTConfig
	Email     EmailConfig
	RateLimit RateLimitConfig
}

type DatabaseConfig struct {
	User     string
	Password string
	Host     string
	Port     string
	Name     string
}

type JWTConfig struct {
	SignKey    string
	RefreshKey string
	ResetKey   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

type EmailConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	From        string
	EnableEmail bool
	EnableLogs  bool
}

type RateLimitConfig struct {
	Register       string
	Login          string
	ForgotPassword string
}

func LoadConfig() *Config {
	zap.L().Info("Loading application configuration")

	emailPortStr := getEnv("EMAIL_PORT", "587")
	emailPort, err := strconv.Atoi(emailPortStr)
	if err != nil {
		zap.L().Fatal("Invalid EMAIL_PORT environment variable",
			zap.String("value", emailPortStr),
			zap.Error(err),
		)
	}

	cfg := &Config{
		Database: DatabaseConfig{
			User:     getEnv("DB_USER", ""),
			Password: getEnv("DB_PASS", ""),
			Host:     getEnv("DB_HOST", ""),
			Port:     getEnv("DB_PORT", ""),
			Name:     getEnv("DB_NAME", ""),
		},
		JWT: JWTConfig{
			SignKey:    "",
			RefreshKey: "",
			ResetKey:   "",
			AccessTTL:  24 * time.Hour,
			RefreshTTL: 7 * 24 * time.Hour,
		},
		Email: EmailConfig{
			Host:        getEnv("EMAIL_HOST", ""),
			Port:        emailPort,
			Username:    getEnv("EMAIL_USERNAME", ""),
			Password:    getEnv("EMAIL_PASSWORD", ""),
			From:        getEnv("EMAIL_FROM", ""),
			EnableEmail: getEnv("ENABLE_EMAIL", "") == "true",
			EnableLogs:  getEnv("ENABLE_LOGS", "") == "true",
		},
		RateLimit: RateLimitConfig{
			Register:       getEnv("RATE_LIMIT_REGISTER", ""),
			Login:          getEnv("RATE_LIMIT_LOGIN", ""),
			ForgotPassword: getEnv("RATE_LIMIT_FORGOT_PASSWORD", ""),
		},
	}

	zap.L().Info("Configuration loaded successfully",
		zap.String("db_host", cfg.Database.Host),
		zap.String("email_host", cfg.Email.Host),
		zap.Bool("email_enabled", cfg.Email.EnableEmail),
		zap.Bool("logging_enabled", cfg.Email.EnableLogs),
	)

	return cfg
}

func (c *Config) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		c.Database.User, c.Database.Password,
		c.Database.Host, c.Database.Port,
		c.Database.Name)
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
