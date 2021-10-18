package main

import (
	"fmt"
	"log"
	"os"
	"time"

	bootstrap "auth_server/bootstrap"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

// @title Authentication Server
// @version 1.0
// @description Authentication API Service.

// @host auth.hiringo.tech
// @BasePath /

// @contact.name Emin Muhammadi
// @contact.url https://github.com/softech-craftsman-webapp/auth_server
// @contact.email admin@hiringo.tech

// @securityDefinitions.apiKey JWT
// @in header
// @name Authorization
func main() {
	// Load .env file
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println(".env file is not imported, in production kindly ignore this message")
	}

	// Set timezone globally
	if tz := os.Getenv("TZ"); tz != "" {
		var err error
		time.Local, err = time.LoadLocation(tz)
		if err != nil {
			log.Printf("error loading location '%s': %v\n", tz, err)
		}
	}

	/*
	   |--------------------------------------------------------------------------
	   | Start Server
	   |--------------------------------------------------------------------------
	*/
	app := echo.New()
	port := os.Getenv("PORT")

	// Application
	bootstrap.Start(app, port)
}
