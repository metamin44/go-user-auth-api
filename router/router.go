package router

import (
	"context"
	"log"
	"net/http"
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
	e.IPExtractor = echo.ExtractIPDirect()

	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `time=${time_rfc3339} method=${method} path=${path} status=${status} latency=${latency_human} remote_ip=${remote_ip}` + "\n",
	}))
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
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

	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.GET("/admin/dashboard", h.AdminDashboard,
		middle.JWTMiddleware(cfg, userRepo),
		middle.RequireRole("admin"),
	)

	e.PUT("/admin/promote", h.PromoteToAdmin,
		middle.JWTMiddleware(cfg, userRepo),
		middle.RequireRole("admin"),
	)

	e.POST("/forgot-password", h.ForgotPassword, forgotPassLimiter)
	e.GET("/reset-password", h.ShowResetPasswordPage)
	e.POST("/reset-password", h.ResetPassword, resetPasswordLimiter)

	auth := e.Group("/auth")
	auth.Use(middle.JWTMiddleware(cfg, userRepo))

	auth.GET("/profile", h.Profile)
	auth.PUT("/update", h.UpdateUser)
	auth.DELETE("/delete", h.DeleteUser)
	auth.POST("/change-password", h.ChangePassword)

	return e

}
