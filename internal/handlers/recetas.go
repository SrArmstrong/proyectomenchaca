package handlers

import (
	"context"
	"fmt"
	"proyectomenchaca/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
)

type Receta struct {
	IDConsultorio int    `json:"id_consultorio"`
	IDMedico      int    `json:"id_medico"`
	IDPaciente    int    `json:"id_paciente"`
	Fecha         string `json:"fecha"`
	Medicamento   string `json:"medicamento"`
	Dosis         string `json:"dosis"`
}

type Recetas struct {
	IDReceta      int    `json:"id_receta"`
	IDConsultorio int    `json:"id_consultorio"`
	IDMedico      int    `json:"id_medico"`
	IDPaciente    int    `json:"id_paciente"`
	Fecha         string `json:"fecha"`
	Medicamento   string `json:"medicamento"`
	Dosis         string `json:"dosis"`
}

func CreateReceta(c *fiber.Ctx) error {
	var receta Receta

	if err := c.BodyParser(&receta); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `INSERT INTO recetas 
	          (id_consultorio, id_medico, id_paciente, fecha, medicamento, dosis) 
	          VALUES ($1, $2, $3, $4, $5, $6) RETURNING id_receta`

	var id int
	err := DB.QueryRow(context.Background(), query,
		receta.IDConsultorio, receta.IDMedico, receta.IDPaciente,
		receta.Fecha, receta.Medicamento, receta.Dosis).Scan(&id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al crear receta",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":      id,
		"mensaje": "Receta creada correctamente",
	})
}

func GetReceta(c *fiber.Ctx) error {
	id := c.Params("id")

	var receta Receta
	query := `SELECT id_consultorio, id_medico, id_paciente, fecha, medicamento, dosis 
	          FROM recetas WHERE id_receta=$1`

	err := DB.QueryRow(context.Background(), query, id).Scan(
		&receta.IDConsultorio,
		&receta.IDMedico,
		&receta.IDPaciente,
		&receta.Fecha,
		&receta.Medicamento,
		&receta.Dosis,
	)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Receta no encontrada",
		})
	}

	return c.JSON(receta)
}

func GetAllRecetas(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(*models.Claims)

	rol := claims.Rol
	idUsuario := claims.IDUsuario

	fmt.Printf("Token claims - IDUsuario: %d, Rol: %s\n", idUsuario, rol)

	var query string
	var rows pgx.Rows
	var err error

	if rol == "paciente" {
		query = `SELECT id_receta, id_consultorio, id_medico, id_paciente, fecha, medicamento, dosis
                 FROM recetas WHERE id_paciente = $1 ORDER BY fecha DESC`
		rows, err = DB.Query(context.Background(), query, idUsuario)
	} else if rol == "medico" {
		query = `SELECT id_receta, id_consultorio, id_medico, id_paciente, fecha, medicamento, dosis
                 FROM recetas WHERE id_medico = $1 ORDER BY fecha DESC`
		rows, err = DB.Query(context.Background(), query, idUsuario)
	} else {
		query = `SELECT id_receta, id_consultorio, id_medico, id_paciente, fecha, medicamento, dosis
                 FROM recetas ORDER BY fecha DESC`
		rows, err = DB.Query(context.Background(), query)
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al consultar las recetas",
		})
	}
	defer rows.Close()

	var recetas []Recetas
	for rows.Next() {
		var receta Recetas
		err := rows.Scan(
			&receta.IDReceta,
			&receta.IDConsultorio,
			&receta.IDMedico,
			&receta.IDPaciente,
			&receta.Fecha,
			&receta.Medicamento,
			&receta.Dosis,
		)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Error al leer los datos de las recetas",
			})
		}
		recetas = append(recetas, receta)
	}

	return c.JSON(fiber.Map{
		"data":  recetas,
		"count": len(recetas),
	})
}

func UpdateReceta(c *fiber.Ctx) error {
	id := c.Params("id")
	var receta Receta

	if err := c.BodyParser(&receta); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `UPDATE recetas 
	          SET id_consultorio=$1, id_medico=$2, id_paciente=$3, 
	              fecha=$4, medicamento=$5, dosis=$6 
	          WHERE id_receta=$7`

	_, err := DB.Exec(context.Background(), query,
		receta.IDConsultorio, receta.IDMedico, receta.IDPaciente,
		receta.Fecha, receta.Medicamento, receta.Dosis, id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al actualizar receta",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Receta actualizada correctamente",
	})
}

func DeleteReceta(c *fiber.Ctx) error {
	id := c.Params("id")

	_, err := DB.Exec(context.Background(), "DELETE FROM recetas WHERE id_receta=$1", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al eliminar receta",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Receta eliminada correctamente",
	})
}
