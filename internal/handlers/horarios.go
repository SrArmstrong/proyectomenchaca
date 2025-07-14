package handlers

import (
	"context"
	"proyectomenchaca/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type Horario struct {
	IDHorario     int    `json:"id_horario"`
	IDConsultorio int    `json:"id_consultorio"`
	IDMedico      int    `json:"id_medico"`
	IDConsulta    int    `json:"id_consulta"`
	Turno         string `json:"turno"`
	Dia           string `json:"dia"`
}

func CreateHorario(c *fiber.Ctx) error {
	var horario Horario

	if err := c.BodyParser(&horario); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `INSERT INTO horarios (id_consultorio, id_medico, id_consulta, turno, dia) 
	          VALUES ($1, $2, $3, $4, $5) RETURNING id_horario`

	var id int
	err := DB.QueryRow(context.Background(), query,
		horario.IDConsultorio, horario.IDMedico, horario.IDConsulta, horario.Turno, horario.Dia).Scan(&id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al crear horario",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":      id,
		"mensaje": "Horario creado correctamente",
	})
}

func GetAllHorarios(c *fiber.Ctx) error {
	// Obtener información del usuario desde el token
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(*models.Claims)
	rol := claims.Rol
	idUsuario := claims.IDUsuario

	var query string
	var args []interface{}
	var err error

	// Construir la consulta según el rol del usuario
	switch rol {
	case "paciente":
		// Paciente: solo horarios de sus consultas
		query = `
            SELECT h.id_horario, h.id_consultorio, h.id_medico, h.id_consulta, h.turno, h.dia 
            FROM horarios h
            JOIN consultas c ON h.id_consulta = c.id_consulta
            WHERE c.id_paciente = $1
            ORDER BY h.dia, h.turno`
		args = []interface{}{idUsuario}

	case "medico":
		// Médico: solo sus horarios
		query = `
            SELECT id_horario, id_consultorio, id_medico, id_consulta, turno, dia 
            FROM horarios 
            WHERE id_medico = $1
            ORDER BY dia, turno`
		args = []interface{}{idUsuario}

	case "admin", "enfermera":
		// Admin y Enfermera: todos los horarios
		query = `
            SELECT id_horario, id_consultorio, id_medico, id_consulta, turno, dia 
            FROM horarios 
            ORDER BY dia, turno`

	default:
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "No tienes permisos para ver horarios",
		})
	}

	// Ejecutar la consulta
	rows, err := DB.Query(context.Background(), query, args...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Error al obtener los horarios",
			"details": err.Error(),
		})
	}
	defer rows.Close()

	var horarios []Horario
	for rows.Next() {
		var h Horario
		err := rows.Scan(&h.IDHorario, &h.IDConsultorio, &h.IDMedico, &h.IDConsulta, &h.Turno, &h.Dia)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Error al procesar los datos",
				"details": err.Error(),
			})
		}
		horarios = append(horarios, h)
	}

	// Verificar errores después de iterar
	if err := rows.Err(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Error después de leer horarios",
			"details": err.Error(),
		})
	}

	return c.JSON(horarios)
}

func GetHorario(c *fiber.Ctx) error {
	id := c.Params("id")

	var horario Horario
	query := `SELECT id_consultorio, id_medico, id_consulta, turno, dia 
	          FROM horarios WHERE id_horario=$1`

	err := DB.QueryRow(context.Background(), query, id).Scan(
		&horario.IDConsultorio,
		&horario.IDMedico,
		&horario.IDConsulta,
		&horario.Turno,
		&horario.Dia,
	)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Horario no encontrado",
		})
	}

	return c.JSON(horario)
}

func UpdateHorario(c *fiber.Ctx) error {
	id := c.Params("id")
	var horario Horario

	if err := c.BodyParser(&horario); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	query := `UPDATE horarios 
	          SET id_consultorio=$1, id_medico=$2, id_consulta=$3, turno=$4, dia=$5 
	          WHERE id_horario=$6`

	_, err := DB.Exec(context.Background(), query,
		horario.IDConsultorio, horario.IDMedico, horario.IDConsulta,
		horario.Turno, horario.Dia, id)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al actualizar horario",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Horario actualizado correctamente",
	})
}

func DeleteHorario(c *fiber.Ctx) error {
	id := c.Params("id")

	_, err := DB.Exec(context.Background(), "DELETE FROM horarios WHERE id_horario=$1", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al eliminar horario",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Horario eliminado correctamente",
	})
}

func GetHorariosDisponibles(c *fiber.Ctx) error {
	rows, err := DB.Query(context.Background(),
		"SELECT id_horario, id_consultorio, turno, dia FROM horarios WHERE id_consulta IS NULL")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al obtener horarios",
		})
	}
	defer rows.Close()

	var horarios []map[string]interface{}
	for rows.Next() {
		var id, idConsultorio int
		var turno, dia string
		err := rows.Scan(&id, &idConsultorio, &turno, &dia)
		if err != nil {
			continue
		}
		horarios = append(horarios, map[string]interface{}{
			"id":             id,
			"id_consultorio": idConsultorio,
			"turno":          turno,
			"dia":            dia,
		})
	}

	return c.JSON(horarios)
}
