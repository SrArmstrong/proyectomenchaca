package handlers

import (
	"context"
	"fmt"
	"proyectomenchaca/internal/models"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
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

	// Determinar turno
	turno := ""
	horaParsed, err := time.Parse("15:04", consulta.Hora)
	if err == nil {
		if horaParsed.Hour() >= 9 && horaParsed.Hour() <= 14 {
			turno = "matutino"
		} else if horaParsed.Hour() >= 15 && horaParsed.Hour() <= 22 {
			turno = "vespertino"
		}
	}

	// Insertar en horarios
	queryHorarios := `INSERT INTO horarios 
						(id_consultorio, id_medico, id_consulta, dia, turno)
						VALUES ($1, $2, $3, $4, $5)`

	_, err = DB.Exec(context.Background(), queryHorarios,
		consulta.IDConsultorio, consulta.IDMedico, id, consulta.Fecha, turno)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al registrar horario",
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
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(*models.Claims)

	rol := claims.Rol
	idUsuario := claims.IDUsuario

	fmt.Printf("Token claims - IDUsuario: %d, Rol: %s\n", idUsuario, rol)

	var query string
	var rows pgx.Rows
	var err error

	if rol == "paciente" {
		query = `SELECT * FROM consultas WHERE id_paciente = $1 ORDER BY fecha DESC, hora DESC`
		rows, err = DB.Query(context.Background(), query, idUsuario)
	} else if rol == "medico" {
		query = `SELECT * FROM consultas WHERE id_medico = $1 ORDER BY fecha DESC, hora DESC`
		rows, err = DB.Query(context.Background(), query, idUsuario)
	} else {
		query = `SELECT * FROM consultas ORDER BY fecha DESC, hora DESC`
		rows, err = DB.Query(context.Background(), query)
	}

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
	var requestData map[string]interface{}

	if err := c.BodyParser(&requestData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Error al parsear datos: " + err.Error(),
		})
	}

	// Validar campos requeridos
	requiredFields := []string{"id_consultorio", "id_medico", "id_paciente", "tipo", "fecha", "hora", "diagnostico", "costo"}
	for _, field := range requiredFields {
		if _, exists := requestData[field]; !exists {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Campo requerido faltante: " + field,
			})
		}
	}

	// Convertir campos numéricos
	idConsultorio, ok := requestData["id_consultorio"].(float64)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "id_consultorio debe ser un número",
		})
	}

	idMedico, ok := requestData["id_medico"].(float64)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "id_medico debe ser un número",
		})
	}

	idPaciente, ok := requestData["id_paciente"].(float64)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "id_paciente debe ser un número",
		})
	}

	costo, ok := requestData["costo"].(float64)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "costo debe ser un número",
		})
	}

	query := `UPDATE consultas 
              SET id_consultorio=$1, id_medico=$2, id_paciente=$3, tipo=$4, 
                  fecha=$5, hora=$6, diagnostico=$7, costo=$8 
              WHERE id_consulta=$9`

	_, err := DB.Exec(context.Background(), query,
		int(idConsultorio),
		int(idMedico),
		int(idPaciente),
		requestData["tipo"].(string),
		requestData["fecha"].(string),
		requestData["hora"].(string),
		requestData["diagnostico"].(string),
		costo,
		id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al actualizar consulta: " + err.Error(),
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
