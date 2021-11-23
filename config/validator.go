package config

import (
	"fmt"
	"net/http"

	"github.com/go-playground/validator"
	"github.com/labstack/echo/v4"
)

type CustomValidator struct {
	Validator *validator.Validate
}

/*
   |--------------------------------------------------------------------------
   | Validator
   |--------------------------------------------------------------------------
*/
func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.Validator.Struct(i); err != nil {
		customError := "Fatal Error"

		if _, ok := err.(*validator.InvalidValidationError); ok {
			customError = "Internal Server Error"
		}

		for _, err := range err.(validator.ValidationErrors) {
			customError = fmt.Sprintf("Validation failed on %v field", err.Value())
		}

		// Optionally, you could return the error to give each route more control over the status code
		return echo.NewHTTPError(http.StatusBadRequest, customError)
	}
	return nil
}

/*
   |--------------------------------------------------------------------------
   | Bind and Validate
   |--------------------------------------------------------------------------
*/
func BindAndValidate(ctx echo.Context, i interface{}) error {
	if err := ctx.Bind(i); err != nil {
		return err
	}

	if err := ctx.Validate(i); err != nil {
		return err
	}

	return nil
}
