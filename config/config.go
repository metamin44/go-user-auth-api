package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ulule/limiter/v3"
	"go.uber.org/zap"
)

// minJWTKeyLength is the minimum accepted length for HMAC-SHA256 signing keys.
// HS256 requires a key of at least 256 bits (32 bytes) to resist brute force.
const minJWTKeyLength = 32

type Config struct {
	AppPort            string
	Database           DatabaseConfig
	JWT                JWTConfig
	Email              EmailConfig
	RateLimit          RateLimitConfig
	CORSAllowedOrigins []string
	EnableSwagger      bool
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
	ResetURL    string
	EnableEmail bool
}

type RateLimitConfig struct {
	Register       string
	Login          string
	ForgotPassword string
	Refresh        string
	ResetPassword  string
}

// LoadConfig reads configuration from the environment and fails fast when
// required settings are missing or insecure, so the process never starts in a
// state where authentication would silently fail at runtime.
func LoadConfig() (*Config, error) {
	zap.L().Info("Loading application configuration")

	emailPort, err := parsePort(getEnv("EMAIL_PORT", "587"))
	if err != nil {
		return nil, fmt.Errorf("invalid EMAIL_PORT: %w", err)
	}

	accessTTL, err := time.ParseDuration(getEnv("JWT_ACCESS_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_ACCESS_TTL: %w", err)
	}

	refreshTTL, err := time.ParseDuration(getEnv("JWT_REFRESH_TTL", "168h"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_REFRESH_TTL: %w", err)
	}

	corsOrigins, err := parseCORSOrigins(getEnv("CORS_ALLOWED_ORIGINS", ""))
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		AppPort: getEnv("APP_PORT", "8082"),

		Database: DatabaseConfig{
			User:     getEnv("DB_USER", ""),
			Password: getEnv("DB_PASS", ""),
			Host:     getEnv("DB_HOST", ""),
			Port:     getEnv("DB_PORT", ""),
			Name:     getEnv("DB_NAME", ""),
		},

		JWT: JWTConfig{
			SignKey:    getEnv("JWT_SIGN_KEY", ""),
			RefreshKey: getEnv("JWT_REFRESH_KEY", ""),
			ResetKey:   getEnv("JWT_RESET_KEY", ""),
			AccessTTL:  accessTTL,
			RefreshTTL: refreshTTL,
		},

		Email: EmailConfig{
			Host:        getEnv("EMAIL_HOST", ""),
			Port:        emailPort,
			Username:    getEnv("EMAIL_USERNAME", ""),
			Password:    getEnv("EMAIL_PASSWORD", ""),
			From:        getEnv("EMAIL_FROM", ""),
			ResetURL:    getEnv("RESET_PASSWORD_URL", "http://localhost:8085/reset-password"),
			EnableEmail: getEnv("ENABLE_EMAIL", "") == "true",
		},

		// Secure, valid defaults so the app starts even when these are unset.
		RateLimit: RateLimitConfig{
			Register:       getEnv("RATE_LIMIT_REGISTER", "3-M"),
			Login:          getEnv("RATE_LIMIT_LOGIN", "5-M"),
			ForgotPassword: getEnv("RATE_LIMIT_FORGOT_PASSWORD", "2-M"),
			Refresh:        getEnv("RATE_LIMIT_REFRESH", "10-M"),
			ResetPassword:  getEnv("RATE_LIMIT_RESET_PASSWORD", "5-M"),
		},

		CORSAllowedOrigins: corsOrigins,
		// Swagger is opt-in; keep API documentation disabled unless explicitly enabled.
		EnableSwagger: getEnv("ENABLE_SWAGGER", "") == "true",
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	zap.L().Info("Configuration loaded successfully",
		zap.String("db_host", cfg.Database.Host),
		zap.String("email_host", cfg.Email.Host),
		zap.Bool("email_enabled", cfg.Email.EnableEmail),
		zap.Duration("access_ttl", cfg.JWT.AccessTTL),
		zap.Duration("refresh_ttl", cfg.JWT.RefreshTTL),
	)

	return cfg, nil
}

// validate rejects missing or insecure configuration before the server starts.
// Error messages never include secret values.
func (c *Config) validate() error {
	if _, err := parsePort(c.AppPort); err != nil {
		return fmt.Errorf("invalid APP_PORT: %w", err)
	}

	if c.Database.User == "" || c.Database.Password == "" ||
		c.Database.Host == "" || c.Database.Name == "" {
		return errors.New("DB_USER, DB_PASS, DB_HOST and DB_NAME are required")
	}

	if _, err := parsePort(c.Database.Port); err != nil {
		return fmt.Errorf("invalid DB_PORT: %w", err)
	}

	if len(c.JWT.SignKey) < minJWTKeyLength ||
		len(c.JWT.RefreshKey) < minJWTKeyLength ||
		len(c.JWT.ResetKey) < minJWTKeyLength {
		return fmt.Errorf("JWT_SIGN_KEY, JWT_REFRESH_KEY and JWT_RESET_KEY must each be at least %d characters", minJWTKeyLength)
	}

	if c.JWT.AccessTTL <= 0 || c.JWT.RefreshTTL <= 0 {
		return errors.New("JWT_ACCESS_TTL and JWT_REFRESH_TTL must be positive durations")
	}

	if c.JWT.AccessTTL > c.JWT.RefreshTTL {
		return errors.New("JWT_ACCESS_TTL must not exceed JWT_REFRESH_TTL")
	}

	if c.Email.EnableEmail {
		if c.Email.Host == "" || c.Email.Username == "" ||
			c.Email.Password == "" || c.Email.From == "" || c.Email.ResetURL == "" {
			return errors.New("EMAIL_HOST, EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_FROM and RESET_PASSWORD_URL are required when ENABLE_EMAIL=true")
		}
	}

	rates := map[string]string{
		"RATE_LIMIT_REGISTER":        c.RateLimit.Register,
		"RATE_LIMIT_LOGIN":           c.RateLimit.Login,
		"RATE_LIMIT_FORGOT_PASSWORD": c.RateLimit.ForgotPassword,
		"RATE_LIMIT_REFRESH":         c.RateLimit.Refresh,
		"RATE_LIMIT_RESET_PASSWORD":  c.RateLimit.ResetPassword,
	}
	for name, rate := range rates {
		if _, err := limiter.NewRateFromFormatted(rate); err != nil {
			return fmt.Errorf("invalid %s: %w", name, err)
		}
	}

	return nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be a number between 1 and 65535")
	}
	return port, nil
}

// parseCORSOrigins accepts a comma-separated origin whitelist. Wildcards are
// rejected: cross-origin access must be granted to explicit origins only.
func parseCORSOrigins(value string) ([]string, error) {
	var origins []string
	for _, origin := range strings.Split(value, ",") {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		if origin == "*" {
			return nil, errors.New("CORS_ALLOWED_ORIGINS must list explicit origins, not '*'")
		}
		if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return nil, fmt.Errorf("CORS_ALLOWED_ORIGINS entries must include http:// or https:// scheme")
		}
		origins = append(origins, origin)
	}
	return origins, nil
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
