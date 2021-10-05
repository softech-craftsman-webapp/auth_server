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
   | Get user and generate token
   | @Post {email, password}
   |--------------------------------------------------------------------------
*/
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,max=64,min=8"`
}

// Authenticate user
// @Tags auth
// @Description Authenticate user
// @Accept  json
// @Produce  json
// @Param user body LoginRequest true "User email and password"
// @Success 200 {object} view.Response{payload=view.LoginAuthView}
// @Failure 400,401,404,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /auth/login [post]
func Login(ctx echo.Context) error {
	db := config.GetDB()

	req := new(LoginRequest)

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
		Email:    req.Email,
		Password: req.Password,
	}

	password := user.Password
	expiration := time.Now().Add(time.Minute * controller.ACCESS_TOKEN_VALID_MINUTE).Unix()
	result := db.Table("users").Where("email = ?", user.Email).First(&user)

	/*
	   |--------------------------------------------------------------------------
	   | Verify password hash
	   |--------------------------------------------------------------------------
	*/
	err := auth.VerifyPassword(user.Password, string(password))

	/*
	   |--------------------------------------------------------------------------
	   | Hash is invalid
	   |--------------------------------------------------------------------------
	*/
	if err != nil {
		resp := &view.Response{
			Success: false,
			Message: "Email or password is invalid",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusBadRequest, ctx, resp)
	}

	/*
	   |--------------------------------------------------------------------------
	   | Auth Token Generation
	   |--------------------------------------------------------------------------
	*/
	auth_token := &model.Auth{}
	db.Where("user_id = ?", user.ID).First(&auth_token)

	token := auth.GenerateSalt(user.Email, user.ID)
	auth_token_result := db.Model(&auth_token).Where("user_id = ? AND id = ?", user.ID, auth_token.ID).Update("token", token)

	user.Auth.ID = auth_token.ID
	user.Auth.Token = token

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
	   | JWT Token Generation
	   |--------------------------------------------------------------------------
	*/
	token, err_token := auth.CreateAccessToken(
		view.UserModeltoView(user),
		controller.ACCESS_TOKEN_VALID_MINUTE)

	refresh_token, err_refresh_token := auth.CreateRefreshToken(
		view.UserModeltoView(user),
		controller.REFRESH_TOKEN_VALID_MINUTE)

	resp := &view.Response{
		Success: true,
		Message: "Success",
		Payload: &view.LoginAuthView{
			ID:              user.ID,
			Email:           user.Email,
			Name:            user.Name,
			EmailVerifiedAt: user.EmailVerifiedAt,
			Token:           token,
			TokenExpiration: expiration,
			RefreshToken:    refresh_token,
		},
	}

	/*
	   |--------------------------------------------------------------------------
	   | Main Error
	   |--------------------------------------------------------------------------
	*/
	if result.Error != nil || err_token != nil || err_refresh_token != nil {
		resp := &view.Response{
			Success: true,
			Message: "Email or password is invalid",
			Payload: nil,
		}
		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusNotFound, ctx, resp)
	}

	// close db
	config.CloseDB(db).Close()

	return view.ApiView(http.StatusOK, ctx, resp)
}
