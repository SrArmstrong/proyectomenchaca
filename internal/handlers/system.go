package handlers

import "github.com/gofiber/fiber/v2"

func SystemInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"sistema": "Go + Fiber",
		"estado":  "OK",
	})
}
