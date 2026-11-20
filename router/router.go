package router

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"reg/config"
	"reg/handler"
	middle "reg/middleware"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	echoSwagger "github.com/swaggo/echo-swagger"
)

func NewRouter(h *handler.UserHandler, cfg *config.Config, userRepo middle.TokenUserRepository) *echo.Echo {
	e := echo.New()
	// Use the direct connection IP. Behind a reverse proxy all requests would
	// share the proxy IP; deploying behind a proxy requires an explicit,
	// trusted-proxy IP extractor configuration (see README).
	e.IPExtractor = echo.ExtractIPDirect()

	// RequestLoggerWithConfig replaces the deprecated LoggerWithConfig
	// (Echo >= v4.16). The custom function preserves the historical
	// access-log format and stdout destination. URIPath matches the legacy
	// ${path} tag (req.URL.Path), including unmatched 404 requests, and
	// excludes the query string so tokens in URLs are never logged.
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogMethod:   true,
		LogURIPath:  true,
		LogStatus:   true,
		LogLatency:  true,
		LogRemoteIP: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			_, err := fmt.Fprintf(os.Stdout,
				"time=%s method=%s path=%s status=%d latency=%s remote_ip=%s\n",
				v.StartTime.Format(time.RFC3339), v.Method, v.URIPath, v.Status, v.Latency, v.RemoteIP)
			return err
		},
	}))
	e.Use(middleware.Recover())
	// Reject oversized request bodies before they are read into memory.
	e.Use(middleware.BodyLimit("1M"))

	// Cross-origin access is denied by default (same-origin only). It is
	// granted only to the explicit whitelist in CORS_ALLOWED_ORIGINS.
	if len(cfg.CORSAllowedOrigins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins: cfg.CORSAllowedOrigins,
			AllowMethods: []string{
				http.MethodGet,
				http.MethodPost,
				http.MethodPut,
				http.MethodDelete,
				http.MethodOptions,
			},
			AllowHeaders: []string{
				echo.HeaderAuthorization,
				echo.HeaderContentType,
			},
			MaxAge: 600,
		}))
	}

	e.Use(middle.MetricsMiddleware)

	// Liveness check: confirms that the application is running.
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status": "ok",
		})
	})

	// Readiness check: confirms that the application can access the database.
	e.GET("/ready", func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
		defer cancel()

		pinger, ok := userRepo.(interface {
			Ping(context.Context) error
		})

		if !ok {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{
				"status": "not ready",
			})
		}

		if err := pinger.Ping(ctx); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{
				"status": "not ready",
			})
		}

		return c.JSON(http.StatusOK, map[string]string{
			"status": "ready",
		})
	})

	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	registerLimiter, err := middle.RateLimiter(cfg.RateLimit.Register)
	if err != nil {
		log.Fatal("Failed to initialize rate limiter: ", err)
	}
	loginLimiter, err := middle.RateLimiter(cfg.RateLimit.Login)
	if err != nil {
		log.Fatal("Failed to initialize rate limiter: ", err)
	}
	forgotPassLimiter, err := middle.RateLimiter(cfg.RateLimit.ForgotPassword)
	if err != nil {
		log.Fatal("Failed to initialize rate limiter: ", err)
	}
	refreshLimiter, err := middle.RateLimiter(cfg.RateLimit.Refresh)
	if err != nil {
		log.Fatal("Failed to initialize refresh rate limiter: ", err)
	}

	resetPasswordLimiter, err := middle.RateLimiter(cfg.RateLimit.ResetPassword)
	if err != nil {
		log.Fatal("Failed to initialize reset password rate limiter: ", err)
	}

	e.POST("/register", h.Register, registerLimiter)
	e.POST("/login", h.Login, loginLimiter)
	e.POST("/refresh", h.RefreshToken, refreshLimiter)

	// Swagger is opt-in via ENABLE_SWAGGER; keep it disabled in production.
	if cfg.EnableSwagger {
		e.GET("/swagger/*", echoSwagger.WrapHandler)
	}

	e.GET("/admin/dashboard", h.AdminDashboard,
		middle.JWTMiddleware(cfg, userRepo),
		middle.RequireRole("admin"),
	)

	e.PUT("/admin/promote", h.PromoteToAdmin,
		middle.JWTMiddleware(cfg, userRepo),
		middle.RequireRole("admin"),
	)

	e.PUT("/admin/demote", h.DemoteAdmin,
		middle.JWTMiddleware(cfg, userRepo),
		middle.RequireRole("admin"),
	)

	e.POST("/forgot-password", h.ForgotPassword, forgotPassLimiter)
	e.GET("/reset-password", h.ShowResetPasswordPage, resetPasswordLimiter)
	e.POST("/reset-password", h.ResetPassword, resetPasswordLimiter)

	auth := e.Group("/auth")
	auth.Use(middle.JWTMiddleware(cfg, userRepo))

	auth.GET("/profile", h.Profile)
	auth.PUT("/update", h.UpdateUser)
	auth.DELETE("/delete", h.DeleteUser)
	auth.POST("/change-password", h.ChangePassword)
	auth.POST("/logout", h.Logout)

	return e

}
