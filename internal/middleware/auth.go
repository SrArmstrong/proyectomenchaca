package middleware

import (
	"context"
	"log"
	"proyectomenchaca/internal/handlers"
	"proyectomenchaca/internal/models"
	"proyectomenchaca/internal/utils"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Permite el acceso a administradores
func OnlyAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*jwt.Token)

		claims, ok := user.Claims.(*models.Claims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Claims inválidos"})
		}

		if claims.Rol != "admin" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Acceso denegado: se requiere rol admin",
			})
		}

		return c.Next()
	}
}

func HasPermission(nombrePermiso string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*jwt.Token)

		claims, ok := user.Claims.(*models.Claims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Claims inválidos"})
		}

		rol := claims.Rol
		db := handlers.GetDB()

		var exists bool
		query := `
			SELECT EXISTS (
				SELECT 1 
				FROM roles_permisos rp
				JOIN permisos p ON rp.id_permiso = p.id_permiso
				WHERE rp.rol = $1 AND p.nombre = $2
			)
		`

		err := db.QueryRow(context.Background(), query, rol, nombrePermiso).Scan(&exists)
		if err != nil || !exists {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Permiso denegado: " + nombrePermiso,
			})
		}

		return c.Next()
	}
}

// Permite el acceso a médicos y administradores
func OnlyMedicoOrAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*jwt.Token)

		claims, ok := user.Claims.(*models.Claims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Claims inválidos"})
		}

		if claims.Rol != "admin" && claims.Rol != "medico" {
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
