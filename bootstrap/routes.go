package bootstrap

import (
	config "auth_server/config"
	controller "auth_server/controller"
	auth_controller "auth_server/controller/auth"
	users_controller "auth_server/controller/users"
	_ "auth_server/docs"

	"github.com/go-playground/validator"
	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger"
)

/*
	|--------------------------------------------------------------------------
	| Routes and its middleware
	|--------------------------------------------------------------------------
*/
func InitRoutes(app *echo.Echo) {
	// Access, Refresh Application Routes
	access_route, refresh_route := config.Guard(app)

	// enable validation
	app.Validator = &config.CustomValidator{Validator: validator.New()}

	// Swagger
	app.GET("/openapi/*", echoSwagger.WrapHandler)
	app.GET("/openapi", controller.SwaggerRedirect)

	// Auth Controller
	// RSA Public Key
	app.GET("/auth/public-key", controller.ServePublicKey)

	app.POST("/auth/register", auth_controller.Register)
	app.POST("/auth/login", auth_controller.Login)
	app.GET("/auth/verify/:token", auth_controller.VerifyEmail)
	app.POST("/auth/forgot-password", auth_controller.ForgotPassword)
	app.POST("/auth/change-password/:token", auth_controller.ChangePassword)
	access_route.POST("/auth/email-resend", auth_controller.EmailResend)
	access_route.POST("/auth/logout", auth_controller.Logout)

	// Refresh Zone
	refresh_route.GET("/auth/refresh", auth_controller.Refresh)

	// User Controller
	access_route.DELETE("/users/:id", users_controller.DeleteUser)
	access_route.GET("/users/:id", users_controller.GetUser)
	access_route.PUT("/users/:id/update-email", users_controller.UpdateEmail)
	access_route.PUT("/users/:id/update-password", users_controller.UpdatePassword)
	access_route.PUT("/users/:id/update-name", users_controller.UpdateName)
}
