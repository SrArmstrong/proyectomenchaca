package handlers

import "github.com/gofiber/fiber/v2"

func Saludo(c *fiber.Ctx) error {
	return c.SendString("Hola mundo desde Fiber")
}
