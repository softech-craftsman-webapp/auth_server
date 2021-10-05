package auth

import (
	"net/http"

	auth "auth_server/auth"
	config "auth_server/config"
	model "auth_server/model"
	view "auth_server/view"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

// Logout
// @Tags auth
// @Description Logout user
// @Accept  json
// @Produce  json
// @Success 201 {object} view.Response{payload=view.UserEmptyView}
// @Failure 400,401,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /auth/logout [post]
// @Security JWT
func Logout(ctx echo.Context) error {
	db := config.GetDB()
	claims := ctx.Get("user").(*jwt.Token).Claims.(*view.JwtCustomClaims)

	/*
	   |--------------------------------------------------------------------------
	   | Auth Token Generation
	   |--------------------------------------------------------------------------
	*/
	auth_token := &model.Auth{}
	db.Where("user_id = ?", claims.User.ID).First(&auth_token)

	token := auth.GenerateSalt(claims.User.Email, claims.User.ID)
	auth_token_result := db.Model(&auth_token).Where("user_id = ? AND id = ?", claims.User.ID, auth_token.ID).Update("token", token)

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

	resp := &view.Response{
		Success: true,
		Message: "Success",
		Payload: &view.UserEmptyView{
			ID: claims.User.ID,
		},
	}

	// close db
	config.CloseDB(db).Close()

	return view.ApiView(http.StatusOK, ctx, resp)
}
