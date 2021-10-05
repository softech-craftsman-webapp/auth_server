package controller

import (
	crypto "auth_server/crypto"
	"net/http"

	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Serve Public Key
   |--------------------------------------------------------------------------
*/
func ServePublicKey(ctx echo.Context) error {
	// @Access
	publicKey := crypto.PublicKeyString()

	return ctx.String(http.StatusOK, string(publicKey))
}
