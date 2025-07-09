package handlers

import (
	"context"
	"proyectomenchaca/internal/models"

	"github.com/gofiber/fiber/v2"
)

type Expediente struct {
	IDPaciente   int    `json:"id_paciente"`
	Antecedentes string `json:"antecedentes"`
	Historial    string `json:"historial"`
	Seguro       string `json:"seguro"`
}

// CreateExpediente crea un nuevo expediente médico
func CreateExpediente(c *fiber.Ctx) error {
	var expediente Expediente

	if err := c.BodyParser(&expediente); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `INSERT INTO expedientes (id_paciente, antecedentes, historial, seguro) 
	          VALUES ($1, $2, $3, $4) RETURNING id_expediente`

	var id int
	err := DB.QueryRow(context.Background(), query,
		expediente.IDPaciente, expediente.Antecedentes, expediente.Historial, expediente.Seguro).Scan(&id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al crear expediente",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":      id,
		"mensaje": "Expediente creado correctamente",
	})
}

// GetExpediente obtiene un expediente por ID
func GetExpediente(c *fiber.Ctx) error {
	id := c.Params("id")

	var expediente Expediente
	query := `SELECT id_paciente, antecedentes, historial, seguro 
	          FROM expedientes WHERE id_expediente=$1`

	err := DB.QueryRow(context.Background(), query, id).Scan(
		&expediente.IDPaciente,
		&expediente.Antecedentes,
		&expediente.Historial,
		&expediente.Seguro,
	)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Expediente no encontrado",
		})
	}

	return c.JSON(expediente)
}

// Trae todos los expedientes
func GetAllExpedientes(c *fiber.Ctx) error {
	query := `SELECT id_expediente, id_paciente, antecedentes, historial, seguro FROM expedientes`

	rows, err := DB.Query(context.Background(), query)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al obtener expedientes",
		})
	}
	defer rows.Close()

	var expedientes []models.Expediente
	for rows.Next() {
		var exp models.Expediente
		err := rows.Scan(&exp.IDExpediente, &exp.IDPaciente, &exp.Antecedentes, &exp.Historial, &exp.Seguro)
		if err != nil {
			continue // podrías registrar el error si quieres
		}
		expedientes = append(expedientes, exp)
	}

	return c.JSON(fiber.Map{
		"status": "ok",
		"data":   expedientes,
	})
}

// UpdateExpediente actualiza un expediente
func UpdateExpediente(c *fiber.Ctx) error {
	id := c.Params("id")
	var expediente Expediente

	if err := c.BodyParser(&expediente); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `UPDATE expedientes 
	          SET antecedentes=$1, historial=$2, seguro=$3 
	          WHERE id_expediente=$4`

	_, err := DB.Exec(context.Background(), query,
		expediente.Antecedentes, expediente.Historial, expediente.Seguro, id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al actualizar expediente",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Expediente actualizado correctamente",
	})
}

// DeleteExpediente elimina un expediente
func DeleteExpediente(c *fiber.Ctx) error {
	id := c.Params("id")

	_, err := DB.Exec(context.Background(), "DELETE FROM expedientes WHERE id_expediente=$1", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al eliminar expediente",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Expediente eliminado correctamente",
	})
}
