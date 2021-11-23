package users

import (
	"net/http"

	config "auth_server/config"
	model "auth_server/model"
	view "auth_server/view"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Delete user
   | @JWT via Acess Token
   | @Param id
   |--------------------------------------------------------------------------
*/
// Delete user
// @Tags users
// @Description Delete user
// @Accept  json
// @Produce  json
// @Param id path string true "User id"
// @Success 200 {object} view.Response{payload=view.UserEmptyView}
// @Failure 400,401,403,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /users/{id} [delete]
// @Security JWT
func DeleteUser(ctx echo.Context) error {
	claims := ctx.Get("user").(*jwt.Token).Claims.(*view.JwtCustomClaims)

	db := config.GetDB()

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

	result := db.Delete(&user)

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
			Success: false,
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
