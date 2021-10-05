package config

import (
	view "auth_server/view"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Message Rewrite
   |--------------------------------------------------------------------------
*/
func GetMessageFromError(value string) string {
	errorMessage := "message="

	pos := strings.LastIndex(value, errorMessage)
	if pos == -1 {
		return ""
	}

	adjustedPos := pos + len(errorMessage)
	if adjustedPos >= len(value) {
		return ""
	}

	return value[adjustedPos:]
}

/*
   |--------------------------------------------------------------------------
   | Custom HTTP Error Handling
   |--------------------------------------------------------------------------
*/
func CustomHTTPErrorHandler(err error, ctx echo.Context) {
	code := http.StatusInternalServerError

	resp := &view.Response{
		Success: false,
		Message: err.Error(),
		Payload: nil,
	}

	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		resp.Message = GetMessageFromError(he.Error())
	}

	if !ctx.Response().Committed {
		if ctx.Request().Method == echo.HEAD {
			err := ctx.NoContent(code)
			if err != nil {
				ctx.Logger().Error(err)
			}
		} else {
			err := view.ApiView(code, ctx, resp)
			if err != nil {
				ctx.Logger().Error(err)
			}
		}
	}
}
