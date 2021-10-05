package auth

import (
	"net/http"
	"time"

	auth "auth_server/auth"
	config "auth_server/config"
	controller "auth_server/controller"
	model "auth_server/model"
	view "auth_server/view"

	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Verify email
   | @Param {token}
   | @Query {email}
   |--------------------------------------------------------------------------
*/
// Verify email
// @Tags auth
// @Description Verify email using token
// @Accept  json
// @Produce  json
// @Param email query string false "User email"
// @Param token path string true "User token"
// @Success 200 {object} view.Response
// @Failure 400,401,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /auth/verify/{token} [get]
func VerifyEmail(ctx echo.Context) error {
	db := config.GetDB()
	token := ctx.Param("token")
	email := ctx.QueryParam("email")

	user := &model.User{}
	user_result := db.First(&user, "email = ?", email)

	/*
	   |--------------------------------------------------------------------------
	   | User not found
	   |--------------------------------------------------------------------------
	*/
	if user_result.Error != nil {
		resp := &view.Response{
			Success: false,
			Message: "Email not found",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusBadRequest, ctx, resp)
	}

	/*
	   |--------------------------------------------------------------------------
	   | Email is already verified
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

	email_verification := &model.Verification{}
	email_verification_result := db.First(&email_verification, "token = ?", token)

	/*
	   |--------------------------------------------------------------------------
	   | Token not found
	   |--------------------------------------------------------------------------
	*/
	if email_verification_result.Error != nil {
		resp := &view.Response{
			Success: false,
			Message: "Token not found",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusBadRequest, ctx, resp)
	}

	/*
	   |--------------------------------------------------------------------------
	   | Validate token
	   |--------------------------------------------------------------------------
	*/
	if !auth.TimeValidation(email_verification.ValidUntil, controller.EMAIL_VERIFICATION_VALID_MINUTE) {
		resp := &view.Response{
			Success: false,
			Message: "Token expired",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusForbidden, ctx, resp)
	}

	resp := &view.Response{
		Success: false,
		Message: "Verification Failed",
		Payload: nil,
	}

	/*
	   |--------------------------------------------------------------------------
	   | Verify token
	   |--------------------------------------------------------------------------
	*/
	if auth.VerifyEmailToken(user.Email, user.ID, email_verification.Salt, token) {
		resp.Success = true
		resp.Message = "Verification Success"

		user.EmailVerifiedAt = (*time.Time)(&email_verification.CreatedAt)
		db.Save(&user)

		return view.ApiView(http.StatusOK, ctx, resp)
	}

	// close db
	config.CloseDB(db).Close()

	return view.ApiView(http.StatusInternalServerError, ctx, resp)
}
