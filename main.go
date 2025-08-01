package main

import (
	"log"
	"reg/config"
	"reg/handler"
	"reg/logger"
	"reg/repository"
	"reg/router"

	_ "net/http/pprof"
	_ "reg/docs"

	"github.com/joho/godotenv"
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

	logger.InitLogger()
	defer logger.Log.Sync()
	logger.Log.Info("Application starting...")

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("warning: No .env file found, using system environment variables.")
	}

	cfg := config.LoadConfig()
	// connect DB
	repo, err := repository.NewUserRepo(cfg)
	if err != nil {
		log.Fatal("failed to connect to database: ", err)
	}
	// create handler
	userHandler := handler.NewUserHandler(repo, cfg, logger.Log)
	e := router.NewRouter(userHandler, cfg)
	// start server
	e.Logger.Fatal(e.Start(":8082"))

}
