package view

import "github.com/labstack/echo/v4"

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Payload interface{} `json:"payload"`
}

func ApiView(code int, ctx echo.Context, r *Response) error {
	response := &Response{
		Success: r.Success,
		Message: r.Message,
		Payload: r.Payload,
	}

	return ctx.JSON(code, response)
}
