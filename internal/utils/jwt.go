package utils

import (
	"os"
	"proyectomenchaca/internal/models"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenExpiry  = 15 * time.Minute   // Token de acceso corto
	RefreshTokenExpiry = 7 * 24 * time.Hour // Token de refresco largo
)

var claveSecreta = []byte("secretKey")

// Crear ambos tokens (acceso y refresh)
func CrearTokens(id int, nombre, rol string) (accessToken, refreshToken string, err error) {
	accessClaims := models.Claims{
		Nombre: nombre,
		Rol:    rol,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.Itoa(id), // 👈 Aquí guardamos el ID
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenExpiry)),
		},
	}

	accessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", "", err
	}

	refreshClaims := models.Claims{
		Nombre: nombre,
		Rol:    rol,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.Itoa(id), // 👈 También en el refresh token
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenExpiry)),
		},
	}

	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// Validar token
func ValidarToken(tokenStr string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenStr, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
}
