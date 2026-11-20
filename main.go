package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"reg/config"
	"reg/handler"
	"reg/internal/metrics"
	"reg/logger"
	"reg/repository"
	"reg/router"

	_ "reg/docs"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

// @title Go User Authentication API
// @version 1.0
// @description A modular monolithic backend in Golang using Echo, MySQL, Docker, and JWT for user authentication.
// @termsOfService http://yourdomain.com/terms/

// @contact.name Your Name
// @contact.url https://your-portfolio.com
// @contact.email your.email@example.com

// @license.name MIT License
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8085
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

func main() {
	if err := run(); err != nil {
		log.Printf("Application stopped with error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	logger.InitLogger()
	defer func() {
		_ = logger.Log.Sync()
	}()

	logger.Log.Info("Application starting...")

	metrics.Init()

	if err := godotenv.Load(); err != nil {
		log.Println("warning: No .env file found, using system environment variables.")
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	repo, err := repository.NewUserRepo(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	defer func() {
		if err := repo.Close(); err != nil {
			logger.Log.Error("Failed to close database connection",
				zap.Error(err),
			)
		}
	}()

	userHandler := handler.NewUserHandler(repo, cfg, logger.Log)
	e := router.NewRouter(userHandler, cfg, repo)

	// Periodically remove expired/revoked sessions so the table does not grow
	// without bound. Stopped before the database connection is closed.
	cleanupCtx, stopCleanup := context.WithCancel(context.Background())
	defer stopCleanup()
	go runSessionCleanup(cleanupCtx, repo)

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- e.Start(":" + cfg.AppPort)
	}()

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server failed: %w", err)
		}
		return nil

	case <-ctx.Done():
		logger.Log.Info("Shutdown signal received")

		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cancel()

		if err := e.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}

		if err := <-serverErr; err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server shutdown failed: %w", err)
		}

		logger.Log.Info("Application stopped gracefully")
		return nil
	}
}

// runSessionCleanup deletes expired and revoked sessions immediately and then
// once per hour until the context is cancelled.
func runSessionCleanup(ctx context.Context, repo *repository.UserRepo) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		deleted, err := repo.DeleteExpiredSessions(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			logger.Log.Error("Session cleanup failed", zap.Error(err))
		case deleted > 0:
			logger.Log.Info("Expired sessions cleaned up", zap.Int64("count", deleted))
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
