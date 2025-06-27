package handlers

import (
	"proyectomenchaca/internal/utils"

	"github.com/gofiber/fiber/v2"
)

type Usuario struct {
	Nombre   string `json:"nombre"`
	Password string `json:"password"`
}

func Register(c *fiber.Ctx) error {
	u := new(Usuario)
	if err := c.BodyParser(u); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Datos inválidos"})
	}
	return c.JSON(fiber.Map{
		"mensaje": "Usuario Registrado",
		"usuario": u.Nombre,
	})
}

func Login(c *fiber.Ctx) error {
	u := new(Usuario)

	if err := c.BodyParser(u); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Datos inválidos"})
	}
	if u.Nombre == "admin" && u.Password == "123456" {
		token, _ := utils.CrearToken(u.Nombre)
		return c.JSON(fiber.Map{"token": token})
	}
	return c.Status(401).JSON(fiber.Map{"error": "Credenciales inválidas"})
}

func LoginInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"mensaje": "Estás autenticado con exito",
	})
}
