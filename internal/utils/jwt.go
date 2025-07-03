package utils

import (
	"os"
	"proyectomenchaca/internal/models"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenExpiry  = 15 * time.Minute   // Token de acceso corto
	RefreshTokenExpiry = 7 * 24 * time.Hour // Token de refresco largo
)

// CrearTokens genera un accessToken y refreshToken personalizados para el usuario
func CrearTokens(id int, nombre, rol string) (accessToken, refreshToken string, err error) {
	accessClaims := models.Claims{
		Nombre: nombre,
		Rol:    rol,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.Itoa(id),
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
			Subject:   strconv.Itoa(id),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenExpiry)),
		},
	}

	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidarToken valida un token JWT y devuelve el token si es válido
func ValidarToken(tokenStr string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenStr, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
}

// OnlyAdmin es un middleware que permite solo a usuarios con rol "admin" acceder
func OnlyAdmin(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)

	claims, ok := token.Claims.(*models.Claims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Claims inválidos"})
	}

	if claims.Rol != "admin" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Acceso restringido a administradores"})
	}

	return c.Next()
}
