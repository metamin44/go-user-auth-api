package router

import (
	"log"
	"reg/config"
	"reg/handler"
	middle "reg/middleware"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	echoSwagger "github.com/swaggo/echo-swagger"
)

func NewRouter(h *handler.UserHandler, cfg *config.Config) *echo.Echo {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

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

	e.POST("/register", h.Register, registerLimiter)
	e.POST("/login", h.Login, loginLimiter)
	e.POST("/refresh", h.RefreshToken)

	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.GET("/admin/dashboard", h.AdminDashboard,
		middle.JWTMiddleware(cfg),
		middle.RequireRole("admin"),
	)

	e.PUT("/admin/promote", h.PromoteToAdmin,
		middle.JWTMiddleware(cfg),
		middle.RequireRole("admin"),
	)

	e.POST("/forgot-password", h.ForgotPassword, forgotPassLimiter)
	e.GET("/reset-password", h.ShowResetPasswordPage)
	e.POST("/reset-password", h.ResetPassword)

	auth := e.Group("/auth")
	auth.Use(middle.JWTMiddleware(cfg))
	auth.GET("/profile", h.Profile)

	auth.PUT("/update", h.UpdateUser)
	auth.DELETE("/delete", h.DeleteUser)
	auth.POST("/change-password", h.ChangePassword)

	return e

}
