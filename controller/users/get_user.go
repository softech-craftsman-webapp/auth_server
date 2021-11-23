package users

import (
	"net/http"

	config "auth_server/config"
	model "auth_server/model"
	view "auth_server/view"

	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Get user by id
   | @JWT via Acess Token
   | @Param id
   |--------------------------------------------------------------------------
*/
// Get user details
// @Tags users
// @Description Get user details
// @Accept  json
// @Produce  json
// @Param id path string true "User id"
// @Success 200 {object} view.Response{payload=view.UserPublicView}
// @Failure 400,401,404,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /users/{id} [get]
// @Header all {string} Token "token"
// @Security JWT
func GetUser(ctx echo.Context) error {
	db := config.GetDB()

	user := &model.User{
		ID: ctx.Param("id"),
	}

	result := db.First(&user)

	resp := &view.Response{
		Success: true,
		Message: "Success",
		Payload: &view.UserPublicView{
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
		},
	}

	if result.Error != nil {
		resp := &view.Response{
			Success: false,
			Message: "User not found",
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
