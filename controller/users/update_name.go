package users

import (
	"net/http"

	auth "auth_server/auth"
	config "auth_server/config"
	model "auth_server/model"
	view "auth_server/view"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

/*
   |--------------------------------------------------------------------------
   | Update name
   | @JWT via Acess Token
   | @Param id
   | @Put name and password
   |--------------------------------------------------------------------------
*/
type UpdateNameRequest struct {
	Name     string `json:"name" validate:"required,max=64,min=2"`
	Password string `json:"password" validate:"required,max=64,min=8"`
}

// Update name
// @Tags users
// @Description Update name
// @Accept  json
// @Produce  json
// @Param id path string true "User id"
// @Param user body UpdateNameRequest true "User name and password"
// @Success 200 {object} view.Response{payload=view.UserEmptyView}
// @Failure 400,401,403,500 {object} view.Response
// @Failure default {object} view.Response
// @Router /users/{id}/update-name [put]
// @Security JWT
func UpdateName(ctx echo.Context) error {
	claims := ctx.Get("user").(*jwt.Token).Claims.(*view.JwtCustomClaims)

	db := config.GetDB()
	req := new(UpdateNameRequest)

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

	result := db.Model(&user).Update("name", req.Name)

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
