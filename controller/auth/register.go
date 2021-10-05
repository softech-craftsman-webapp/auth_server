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
   | Create a new user
   | @Post {name, email, password}
   |--------------------------------------------------------------------------
*/
type RegisterRequest struct {
	Name     string `json:"name" validate:"required,max=64,min=2"`
	Email    string `json:"email" validate:"required,email,max=120"`
	Password string `json:"password" validate:"required,max=64,min=8"`
}

// Create a new user
// @Tags auth
// @Description Create a new user
// @Accept  json
// @Produce  json
// @Param user body RegisterRequest true "User name, email and password"
// @Success 201 {object} view.Response{payload=view.UserPublicView}
// @Failure 400,401,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /auth/register [post]
func Register(ctx echo.Context) error {
	db := config.GetDB()

	req := new(RegisterRequest)

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
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}

	/*
	   |--------------------------------------------------------------------------
	   | Hash generate
	   |--------------------------------------------------------------------------
	*/
	password, err := auth.Hash(user.Password)

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

	result := db.Create(&user)

	/*
	   |--------------------------------------------------------------------------
	   | DB relation error
	   |--------------------------------------------------------------------------
	*/
	if result.Error != nil {
		resp := &view.Response{
			Success: false,
			Message: result.Error.Error(),
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusCreated, ctx, resp)
	}

	auth_token := &model.Auth{
		UserID: user.ID,
		Token:  auth.GenerateSalt(user.Email, user.ID),
	}

	auth_token_result := db.Create(&auth_token)

	if auth_token_result.Error != nil {
		resp := &view.Response{
			Success: false,
			Message: "Auth error",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusInternalServerError, ctx, resp)
	}

	/*
	   |--------------------------------------------------------------------------
	   | Send email
	   |--------------------------------------------------------------------------
	*/
	err = auth.EmailVertification(
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
		Message: "Success",
		Payload: &view.UserPublicView{
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
		},
	}

	// close db
	config.CloseDB(db).Close()

	return view.ApiView(http.StatusCreated, ctx, resp)
}
