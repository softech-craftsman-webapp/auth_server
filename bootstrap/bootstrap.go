package bootstrap

import (
	config "auth_server/config"

	"github.com/labstack/echo/v4"
)

func Start(app *echo.Echo, port string) {
	// db migrate
	config.Migrate()

	InitConfigurations(app)
	InitRoutes(app)
	InitServer(app, port)
}
