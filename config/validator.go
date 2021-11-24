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
type fieldError struct {
	err validator.FieldError
}

/*
   |--------------------------------------------------------------------------
   | ValidatorCustomErrorMessage
   |--------------------------------------------------------------------------
*/
func ValidatorCustomErrorMessage(q fieldError) string {
	return fmt.Sprintf("Validation failed on field %v", q.err.Field())
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
			customError = ValidatorCustomErrorMessage(fieldError{err: err})
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
