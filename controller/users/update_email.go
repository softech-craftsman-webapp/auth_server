package users

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
   | Update email
   | @JWT via Acess Token
   | @Param id
   | @Put email, password
   |--------------------------------------------------------------------------
*/
type UpdateEmailRequest struct {
	Email    string `json:"email" validate:"required,email,max=120"`
	Password string `json:"password" validate:"required,max=64,min=8"`
}

// Update email
// @Tags users
// @Description Update email
// @Accept  json
// @Produce  json
// @Param id path string true "User id"
// @Param user body UpdateEmailRequest true "User email and password"
// @Success 200 {object} view.Response{payload=view.UserEmptyView}
// @Failure 400,401,403,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /users/{id}/update-email [put]
// @Security JWT
func UpdateEmail(ctx echo.Context) error {
	claims := ctx.Get("user").(*jwt.Token).Claims.(*view.JwtCustomClaims)

	db := config.GetDB()
	req := new(UpdateEmailRequest)

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
		ID: ctx.Param("id"),
	}

	db.First(&user, "id = ?", user.ID)

	/*
	   |--------------------------------------------------------------------------
	   | Check if user's id the same as the logged in user
	   |--------------------------------------------------------------------------
	*/
	if user.ID != claims.User.ID {
		resp := &view.Response{
			Success: true,
			Message: "Forbidden",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusForbidden, ctx, resp)
	}

	/*
	   |--------------------------------------------------------------------------
	   | Verify password hash
	   |--------------------------------------------------------------------------
	*/
	err := auth.VerifyPassword(user.Password, string(req.Password))

	/*
	   |--------------------------------------------------------------------------
	   | Hash is invalid
	   |--------------------------------------------------------------------------
	*/
	if err != nil {
		resp := &view.Response{
			Success: false,
			Message: "Old password is invalid",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusBadRequest, ctx, resp)
	}

	result := db.Model(&user).Update("email", req.Email).Update("email_verified_at", nil)

	/*
	   |--------------------------------------------------------------------------
	   | Send email
	   |--------------------------------------------------------------------------
	*/
	err = auth.EmailVertification(
		req.Email,
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
		Message: "Success",
		Payload: &view.UserEmptyView{
			ID: user.ID,
		},
	}

	/*
	   |--------------------------------------------------------------------------
	   | Main Error
	   |--------------------------------------------------------------------------
	*/
	if result.Error != nil {
		resp := &view.Response{
			Success: true,
			Message: "Internal Server Error",
			Payload: nil,
		}
		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusInternalServerError, ctx, resp)
	}

	// close db
	config.CloseDB(db).Close()

	return view.ApiView(http.StatusOK, ctx, resp)
}
