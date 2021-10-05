package controller

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func SwaggerRedirect(ctx echo.Context) error {
	return ctx.Redirect(http.StatusMovedPermanently, "/openapi/index.html")
}
