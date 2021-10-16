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

// @host 127.0.0.1:5000
// @BasePath /

// @securityDefinitions.apiKey JWT
// @in header
// @name Authorization
func main() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println(".env file is not imported, in production kindly ignore this message")
	}

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
