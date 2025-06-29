package middleware

import (
	"log"
	"proyectomenchaca/internal/utils"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Permite el acceso a administradores
func OnlyAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user") // extraído desde JWTProtected()
		claims := user.(*jwt.Token).Claims.(jwt.MapClaims)

		rol, ok := claims["rol"].(string)
		if !ok || rol != "admin" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Acceso denegado: se requiere rol admin",
			})
		}

		return c.Next()
	}
}

// Permite el acceso a médicos y administradores
func OnlyMedicoOrAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user") // extraído desde JWTProtected()
		claims := user.(*jwt.Token).Claims.(jwt.MapClaims)

		rol, ok := claims["rol"].(string)
		if !ok || (rol != "medico" && rol != "admin") {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Acceso denegado: se requiere rol medico o admin",
			})
		}

		return c.Next()
	}
}

// Permite el acceso a todos los usuarios que cuenten con un token
func JWTProtected() fiber.Handler {
	return func(c *fiber.Ctx) error {

		auth := c.Get("Authorization")
		if auth == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Token requerido"})
		}

		partes := strings.Split(auth, " ")
		if len(partes) != 2 || partes[0] != "Bearer" {
			return c.Status(401).JSON(fiber.Map{"error": "Formato de token invalido"})
		}

		tokenStr := partes[1]
		token, err := utils.ValidarToken(tokenStr)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Token inválido"})
		}

		c.Locals("user", token)

		return c.Next()
	}
}

func Logger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		log.Printf("[%s] %s", c.Method(), c.Path())
		return c.Next()
	}
}
