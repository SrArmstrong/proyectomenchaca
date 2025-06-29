package handlers

import (
	"context"

	"github.com/gofiber/fiber/v2"
)

type Consultorio struct {
	IDMedico  int    `json:"id_medico"`
	Tipo      string `json:"tipo"`
	Ubicacion string `json:"ubicacion"`
	Nombre    string `json:"nombre"`
	Telefono  string `json:"telefono"`
}

func CreateConsultorio(c *fiber.Ctx) error {
	var consultorio Consultorio

	if err := c.BodyParser(&consultorio); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `INSERT INTO consultorios (id_medico, tipo, ubicacion, nombre, telefono) 
	          VALUES ($1, $2, $3, $4, $5) RETURNING id_consultorio`

	var id int
	err := DB.QueryRow(context.Background(), query,
		consultorio.IDMedico, consultorio.Tipo, consultorio.Ubicacion,
		consultorio.Nombre, consultorio.Telefono).Scan(&id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al crear consultorio",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":      id,
		"mensaje": "Consultorio creado correctamente",
	})
}

func GetConsultorio(c *fiber.Ctx) error {
	id := c.Params("id")

	var consultorio Consultorio
	query := `SELECT id_medico, tipo, ubicacion, nombre, telefono 
	          FROM consultorios WHERE id_consultorio=$1`

	err := DB.QueryRow(context.Background(), query, id).Scan(
		&consultorio.IDMedico,
		&consultorio.Tipo,
		&consultorio.Ubicacion,
		&consultorio.Nombre,
		&consultorio.Telefono,
	)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Consultorio no encontrado",
		})
	}

	return c.JSON(consultorio)
}

func UpdateConsultorio(c *fiber.Ctx) error {
	id := c.Params("id")
	var consultorio Consultorio

	if err := c.BodyParser(&consultorio); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `UPDATE consultorios 
	          SET id_medico=$1, tipo=$2, ubicacion=$3, nombre=$4, telefono=$5 
	          WHERE id_consultorio=$6`

	_, err := DB.Exec(context.Background(), query,
		consultorio.IDMedico, consultorio.Tipo, consultorio.Ubicacion,
		consultorio.Nombre, consultorio.Telefono, id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al actualizar consultorio",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Consultorio actualizado correctamente",
	})
}

func DeleteConsultorio(c *fiber.Ctx) error {
	id := c.Params("id")

	_, err := DB.Exec(context.Background(), "DELETE FROM consultorios WHERE id_consultorio=$1", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al eliminar consultorio",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Consultorio eliminado correctamente",
	})
}

func GetConsultoriosDisponibles(c *fiber.Ctx) error {
	rows, err := DB.Query(context.Background(),
		"SELECT id_consultorio, nombre, tipo, ubicacion FROM consultorios")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al obtener consultorios",
		})
	}
	defer rows.Close()

	var consultorios []map[string]interface{}
	for rows.Next() {
		var id int
		var nombre, tipo, ubicacion string
		err := rows.Scan(&id, &nombre, &tipo, &ubicacion)
		if err != nil {
			continue
		}
		consultorios = append(consultorios, map[string]interface{}{
			"id":        id,
			"nombre":    nombre,
			"tipo":      tipo,
			"ubicacion": ubicacion,
		})
	}

	return c.JSON(consultorios)
}
