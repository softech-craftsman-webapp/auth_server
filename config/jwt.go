package config

import (
	crypto "auth_server/crypto"
	model "auth_server/model"
	view "auth_server/view"
	"errors"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

/*
   |--------------------------------------------------------------------------
   | Token Validation Middleware
   |--------------------------------------------------------------------------
*/
func TokenValidationMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		claims := ctx.Get("user").(*jwt.Token).Claims.(*view.JwtCustomClaims)

		db := GetDB()
		auth := &model.Auth{}

		auth_result := db.First(&auth, "id = ? AND user_id = ?", claims.User.Auth.ID, claims.User.ID)
		if auth_result.Error != nil {
			// close db
			CloseDB(db).Close()

			return errors.New("auth token not found")
		}

		if claims.User.Auth.Token != auth.Token {
			// close db
			CloseDB(db).Close()

			return errors.New("token is blacklisted")
		}

		// close db
		CloseDB(db).Close()

		return next(ctx)
	}
}

/*
   |--------------------------------------------------------------------------
   | JWT Middleware
   |--------------------------------------------------------------------------
*/
func Guard(app *echo.Echo) (access_route *echo.Group, refresh_route *echo.Group) {
	// Keys
	// @Access
	access_key, error := crypto.AccessPublicKey()
	if error != nil {
		panic(error)
	}

	// @Refresh
	refresh_key, error := crypto.RefreshPublicKey()
	if error != nil {
		panic(error)
	}

	// Routes
	access_route = app.Group("")
	refresh_route = app.Group("")

	// Jwt middleware @Access
	access_route.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		Claims:        &view.JwtCustomClaims{},
		SigningMethod: crypto.SigningMethodName,
		SigningKey:    access_key,
	}))

	// Jwt middleware @Refresh
	refresh_route.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		Claims:        &view.JwtCustomClaims{},
		SigningMethod: crypto.SigningMethodName,
		SigningKey:    refresh_key,
	}))

	// Token Validation
	access_route.Use(TokenValidationMiddleware)
	refresh_route.Use(TokenValidationMiddleware)

	return access_route, refresh_route
}
