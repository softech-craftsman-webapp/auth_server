package view

import (
	"time"

	model "auth_server/model"
)

type UserEmptyView struct {
	ID string `json:"id"`
}

type UserPublicView struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type UserAuthView struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	Auth            AuthView   `json:"auth,omitempty"`
}

type AuthView struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func UserModeltoView(user *model.User) UserAuthView {
	return UserAuthView{
		ID:              user.ID,
		Name:            user.Name,
		Email:           user.Email,
		EmailVerifiedAt: user.EmailVerifiedAt,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
		Auth: AuthView{
			ID:    user.Auth.ID,
			Token: user.Auth.Token,
		},
	}
}
