package bootstrap

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Start app
   |--------------------------------------------------------------------------
*/
func InitServer(app *echo.Echo, port string) {
	go func() {
		if err := app.Start(":" + port); err != nil && err != http.ErrServerClosed {
			app.Logger.Fatal("[Initial Start Error]: Shutting down the server")
		}
	}()

	/*
	   |--------------------------------------------------------------------------
	   | Graceful shutdown
	   |--------------------------------------------------------------------------
	*/
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.Shutdown(ctx); err != nil {
		app.Logger.Fatal(err)
	}
}
