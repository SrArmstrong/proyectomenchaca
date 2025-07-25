package middleware

import (
	"context"
	"proyectomenchaca/internal/handlers"
	"proyectomenchaca/internal/models"
	"proyectomenchaca/internal/utils"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// HasPermission verifica si el usuario tiene un permiso específico
func HasPermission(nombrePermiso string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*jwt.Token)

		claims, ok := user.Claims.(*models.Claims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Claims inválidos"})
		}

		// Verificar si el permiso está en la lista de permisos del token
		permisoEncontrado := false
		for _, permiso := range claims.Permisos {
			if permiso == nombrePermiso {
				permisoEncontrado = true
				break
			}
		}

		if !permisoEncontrado {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Permiso denegado: " + nombrePermiso,
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
			return c.Status(401).JSON(fiber.Map{"error": "Token inválido", "details": err.Error()})
		}

		c.Locals("user", token)

		return c.Next()
	}
}

func Logger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Ejecutar siguiente middleware o handler
		err := c.Next()

		// Aquí capturamos datos de la petición para log
		endpoint := c.Path()
		metodo := c.Method()
		usuario := c.Get("X-User-Email") // o de JWT u otra forma que tengas de identificar usuario
		mensaje := ""                    // opcional, podrías guardar error o info
		direccionIP := c.IP()
		userAgent := c.Get("User-Agent")

		// Llamamos a la función para guardar el log, sin bloquear la petición
		go func() {
			_ = handlers.LogEvent(context.Background(), endpoint, metodo, usuario, mensaje, direccionIP, userAgent)
		}()

		return err
	}
}
