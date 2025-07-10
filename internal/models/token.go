package models

import (
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	IDUsuario int    `json:"id_usuario"`
	Nombre    string `json:"nombre"`
	Rol       string `json:"rol"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}
