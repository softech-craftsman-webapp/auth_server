package view

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type JwtCustomClaims struct {
	User UserAuthView `json:"user"`
	jwt.StandardClaims
}

type LoginAuthView struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Name            string     `json:"name"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	Token           string     `json:"token"`
	TokenExpiration int64      `json:"token_expiration"`
	RefreshToken    string     `json:"refresh_token"`
}

type RefreshTokenView struct {
	Token           string `json:"token"`
	RefreshToken    string `json:"refresh_token"`
	TokenExpiration int64  `json:"token_expiration"`
}
