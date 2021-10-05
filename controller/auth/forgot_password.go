package auth

import (
	"net/http"

	auth "auth_server/auth"
	config "auth_server/config"
	controller "auth_server/controller"
	model "auth_server/model"
	view "auth_server/view"

	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Forgot password
   | @Post {email}
   |--------------------------------------------------------------------------
*/
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email,max=120"`
}

// Forgot password
// @Tags auth
// @Description Forgot password
// @Accept  json
// @Produce  json
// @Param user body ForgotPasswordRequest true "User email"
// @Success 200 {object} view.Response
// @Failure 400,401,404,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /auth/forgot-password [post]
func ForgotPassword(ctx echo.Context) error {
	db := config.GetDB()

	req := new(ForgotPasswordRequest)

	/*
	   |--------------------------------------------------------------------------
	   | Bind request
	   |--------------------------------------------------------------------------
	*/
	if err := config.BindAndValidate(ctx, req); err != nil {
		config.CloseDB(db).Close()

		return ctx.JSON(http.StatusBadRequest, &view.Response{
			Success: false,
			Message: config.GetMessageFromError(err.Error()),
			Payload: nil,
		})
	}

	user := &model.User{
		Email: req.Email,
	}
	user_result := db.First(&user, "email = ?", req.Email)

	/*
	   |--------------------------------------------------------------------------
	   | User not found
	   |--------------------------------------------------------------------------
	*/
	if user_result.Error != nil {
		resp := &view.Response{
			Success: false,
			Message: "User not found",
			Payload: nil,
		}
		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusNotFound, ctx, resp)
	}

	/*
	   |--------------------------------------------------------------------------
	   | Send email
	   |--------------------------------------------------------------------------
	*/
	err := auth.EmailVertification(
		user.Email,
		user.ID,
		controller.EMAIL_VERIFICATION_VALID_MINUTE,
		"RESET-PASSWORD")

	if err != nil {
		resp := &view.Response{
			Success: false,
			Message: err.Error(),
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusInternalServerError, ctx, resp)
	}

	resp := &view.Response{
		Success: true,
		Message: "Verification sent successfully",
		Payload: nil,
	}

	// close db
	config.CloseDB(db).Close()

	return view.ApiView(http.StatusOK, ctx, resp)
}
