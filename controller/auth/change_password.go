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
   | Forgot password
   | @Post {password}
   | @Param {email}
   |--------------------------------------------------------------------------
*/
type ChangePasswordRequest struct {
	Password string `json:"password" validate:"max=64,min=8"`
}

// Verify forgot password
// @Tags auth
// @Description Verify forgot password
// @Accept  json
// @Produce  json
// @Param email query string false "User email"
// @Param token path string true "User token"
// @Param user body ChangePasswordRequest true "User password"
// @Success 200 {object} view.Response
// @Failure 400,401,404,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /auth/change-password/{token} [post]
func ChangePassword(ctx echo.Context) error {
	db := config.GetDB()
	token := ctx.Param("token")
	email := ctx.QueryParam("email")

	req := new(ChangePasswordRequest)

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
			Message: "Email is not found",
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
	   | Password is verified
	   |--------------------------------------------------------------------------
	*/
	if email_verification.VerifiedAt != nil {
		resp := &view.Response{
			Success: false,
			Message: "Password is already changed",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusBadRequest, ctx, resp)
	}

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
		Message: "Password changed",
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

		password, err := auth.Hash(req.Password)

		if err != nil {
			resp := &view.Response{
				Success: false,
				Message: err.Error(),
				Payload: nil,
			}

			// close db
			config.CloseDB(db).Close()

			return view.ApiView(http.StatusBadRequest, ctx, resp)
		}

		user.Password = string(password)
		email_verification.VerifiedAt = (*time.Time)(&user.UpdatedAt)

		db.Save(&email_verification)
		db.Save(&user)

		return view.ApiView(http.StatusOK, ctx, resp)
	}

	// close db
	config.CloseDB(db).Close()

	return view.ApiView(http.StatusInternalServerError, ctx, resp)
}
