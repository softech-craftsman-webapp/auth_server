package auth

import (
	"net/http"

	auth "auth_server/auth"
	config "auth_server/config"
	controller "auth_server/controller"
	model "auth_server/model"
	view "auth_server/view"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Resend email verification
   | @JWT via Access token
   |--------------------------------------------------------------------------
*/
// Resend email
// @Tags auth
// @Description Resend email
// @Accept  json
// @Produce  json
// @Success 200 {object} view.Response
// @Failure 400,401,404,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /auth/email-resend [post]
// @Security JWT
func EmailResend(ctx echo.Context) error {
	db := config.GetDB()
	claims := ctx.Get("user").(*jwt.Token).Claims.(*view.JwtCustomClaims)

	user := &model.User{}
	user_result := db.First(&user, "id = ?", claims.User.ID)

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
	   | Email verification check
	   |--------------------------------------------------------------------------
	*/
	if user.EmailVerifiedAt != nil {
		resp := &view.Response{
			Success: false,
			Message: "Email already verified",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusBadRequest, ctx, resp)
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
		"VERIFY-EMAIL")

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
