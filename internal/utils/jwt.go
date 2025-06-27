package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var claveSecreta = []byte("clave-super-secreta")

func CrearToken(nombre string) (string, error) {
	claims := jwt.MapClaims{
		"user": nombre,
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(claveSecreta)
}

func ValidarToken(tokenStr string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return claveSecreta, nil
	})
}
