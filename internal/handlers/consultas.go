package handlers

import (
	"context"

	"github.com/gofiber/fiber/v2"
)

type Consulta struct {
	IDConsultorio int     `json:"id_consultorio"`
	IDMedico      int     `json:"id_medico"`
	IDPaciente    int     `json:"id_paciente"`
	Tipo          string  `json:"tipo"`
	Fecha         string  `json:"fecha"`
	Hora          string  `json:"hora"`
	Diagnostico   string  `json:"diagnostico"`
	Costo         float64 `json:"costo"`
}

type Consultas struct {
	IDConsulta    int     `json:"id_consulta"`
	IDConsultorio int     `json:"id_consultorio"`
	IDMedico      int     `json:"id_medico"`
	IDPaciente    int     `json:"id_paciente"`
	Tipo          string  `json:"tipo"`
	Fecha         string  `json:"fecha"`
	Hora          string  `json:"hora"`
	Diagnostico   string  `json:"diagnostico"`
	Costo         float64 `json:"costo"`
}

func CreateConsulta(c *fiber.Ctx) error {
	var consulta Consulta

	if err := c.BodyParser(&consulta); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `INSERT INTO consultas 
	          (id_consultorio, id_medico, id_paciente, tipo, fecha, hora, diagnostico, costo) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id_consulta`

	var id int
	err := DB.QueryRow(context.Background(), query,
		consulta.IDConsultorio, consulta.IDMedico, consulta.IDPaciente,
		consulta.Tipo, consulta.Fecha, consulta.Hora, consulta.Diagnostico, consulta.Costo).Scan(&id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al crear consulta",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":      id,
		"mensaje": "Consulta creada correctamente",
	})
}

func GetConsulta(c *fiber.Ctx) error {
	id := c.Params("id")

	var consulta Consulta
	query := `SELECT id_consultorio, id_medico, id_paciente, tipo, fecha, hora, diagnostico, costo 
	          FROM consultas WHERE id_consulta=$1`

	err := DB.QueryRow(context.Background(), query, id).Scan(
		&consulta.IDConsultorio,
		&consulta.IDMedico,
		&consulta.IDPaciente,
		&consulta.Tipo,
		&consulta.Fecha,
		&consulta.Hora,
		&consulta.Diagnostico,
		&consulta.Costo,
	)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Consulta no encontrada",
		})
	}

	return c.JSON(consulta)
}

func GetAllConsultas(c *fiber.Ctx) error {
	query := `SELECT *
	          FROM consultas ORDER BY fecha DESC, hora DESC`

	rows, err := DB.Query(context.Background(), query)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Error al obtener consultas",
			"details": err.Error(),
		})
	}
	defer rows.Close()

	var consultas []Consultas
	for rows.Next() {
		var consulta Consultas
		err := rows.Scan(
			&consulta.IDConsulta,
			&consulta.IDConsultorio,
			&consulta.IDMedico,
			&consulta.IDPaciente,
			&consulta.Tipo,
			&consulta.Fecha,
			&consulta.Hora,
			&consulta.Diagnostico,
			&consulta.Costo,
		)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Error al leer datos de consulta",
				"details": err.Error(),
			})
		}
		consultas = append(consultas, consulta)
	}

	if err := rows.Err(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Error después de leer consultas",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"data":  consultas,
		"count": len(consultas),
	})
}

func UpdateConsulta(c *fiber.Ctx) error {
	id := c.Params("id")
	var consulta Consulta

	if err := c.BodyParser(&consulta); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `UPDATE consultas 
	          SET id_consultorio=$1, id_medico=$2, id_paciente=$3, tipo=$4, 
	              fecha=$5, hora=$6, diagnostico=$7, costo=$8 
	          WHERE id_consulta=$9`

	_, err := DB.Exec(context.Background(), query,
		consulta.IDConsultorio, consulta.IDMedico, consulta.IDPaciente,
		consulta.Tipo, consulta.Fecha, consulta.Hora, consulta.Diagnostico, consulta.Costo, id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al actualizar consulta",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Consulta actualizada correctamente",
	})
}

func DeleteConsulta(c *fiber.Ctx) error {
	id := c.Params("id")

	_, err := DB.Exec(context.Background(), "DELETE FROM consultas WHERE id_consulta=$1", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al eliminar consulta",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Consulta eliminada correctamente",
	})
}
