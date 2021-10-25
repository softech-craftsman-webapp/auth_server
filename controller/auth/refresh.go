package auth

import (
	"net/http"
	"time"

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
   | Refresh token
   | @JWT via Refresh token
   |--------------------------------------------------------------------------
*/
// Refresh token
// @Tags auth
// @Description Get a new access token using refresh token as JWT
// @Accept  json
// @Produce  json
// @Success 201 {object} view.Response{payload=view.RefreshTokenView}
// @Failure 401,403,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /auth/refresh [get]
// @Security JWT
func Refresh(ctx echo.Context) error {
	claims := ctx.Get("user").(*jwt.Token).Claims.(*view.JwtCustomClaims)

	db := config.GetDB()
	expiration := time.Now().Add(time.Minute * controller.ACCESS_TOKEN_VALID_MINUTE).Unix()

	user := &model.User{
		ID: claims.User.ID,
	}

	user_result := db.Table("users").Where("id = ?", user.ID).First(&user)
	if user_result.Error != nil {
		resp := &view.Response{
			Success: false,
			Message: "User not found",
			Payload: nil,
		}

		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusInternalServerError, ctx, resp)
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

	token, err_token := auth.CreateAccessToken(
		view.UserModeltoView(user),
		controller.ACCESS_TOKEN_VALID_MINUTE)

	refresh_token, err_refresh_token := auth.CreateRefreshToken(
		view.UserModeltoView(user),
		controller.REFRESH_TOKEN_VALID_MINUTE)

	resp := &view.Response{
		Success: true,
		Message: "Success",
		Payload: &view.RefreshTokenView{
			Token:           token,
			RefreshToken:    refresh_token,
			TokenExpiration: expiration,
		},
	}

	/*
	   |--------------------------------------------------------------------------
	   | Main Error
	   |--------------------------------------------------------------------------
	*/
	if err_token != nil || err_refresh_token != nil {
		resp := &view.Response{
			Success: true,
			Message: "Token error",
			Payload: nil,
		}
		// close db
		config.CloseDB(db).Close()

		return view.ApiView(http.StatusInternalServerError, ctx, resp)
	}

	return view.ApiView(http.StatusCreated, ctx, resp)
}
