package handlers

import (
	"context"
	"log"
	"proyectomenchaca/internal/models"
	"proyectomenchaca/internal/utils"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var DB *pgxpool.Pool

func SetDB(pool *pgxpool.Pool) {
	DB = pool
}

// Obtiene la información de un usuario por su ID
func Login(c *fiber.Ctx) error {
	var datos models.UsuarioLogin

	if err := c.BodyParser(&datos); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos: " + err.Error(),
		})
	}

	// Obtener dirección IP y User-Agent
	ip := c.IP()
	userAgent := c.Get("User-Agent")

	// Buscar usuario
	var usuario models.UsuarioBD
	err := DB.QueryRow(context.Background(),
		`SELECT id_usuario, nombre, password, rol 
         FROM usuarios WHERE correo = $1`, datos.Correo).Scan(
		&usuario.ID, &usuario.Nombre, &usuario.Password, &usuario.Rol)

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Credenciales inválidas",
		})
	}

	// Verificar contraseña
	if err := bcrypt.CompareHashAndPassword([]byte(usuario.Password), []byte(datos.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Credenciales inválidas",
		})
	}

	// Generar tokens
	accessToken, refreshToken, err := utils.CrearTokens(usuario.ID, usuario.Nombre, usuario.Rol)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error generando tokens: " + err.Error(),
		})
	}

	// Guardar refresh token (adaptado a tu estructura)
	_, err = DB.Exec(context.Background(),
		`INSERT INTO refresh_tokens 
         (usuario_id, token, fecha_creacion, fecha_expiracion, revocado, direccion_ip, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		usuario.ID,
		refreshToken,
		time.Now(),                     // fecha_creacion
		time.Now().Add(7*24*time.Hour), // fecha_expiracion (7 días)
		false,                          // revocado
		ip,                             // direccion_ip
		userAgent,                      // user_agent
	)

	if err != nil {
		log.Printf("Error SQL: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al guardar sesión: " + err.Error(),
		})
	}

	return c.JSON(models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Nuevo handler para refrescar tokens
func RefreshToken(c *fiber.Ctx) error {
	var req models.RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	// Validar token
	token, err := utils.ValidarToken(req.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token inválido: " + err.Error(),
		})
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token inválido",
		})
	}

	// Revocar token anterior
	_, err = DB.Exec(context.Background(),
		`UPDATE refresh_tokens SET revocado = true WHERE token = $1`, req.RefreshToken)

	if err != nil {
		log.Printf("Error al revocar refresh token anterior: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al revocar token anterior",
		})
	}

	// Generar nuevos tokens
	usuarioID, _ := strconv.Atoi(claims.Subject)
	newAccess, newRefresh, err := utils.CrearTokens(usuarioID, claims.Nombre, claims.Rol)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error generando nuevos tokens",
		})
	}

	// Obtener IP y User-Agent actuales
	ip := c.IP()
	userAgent := c.Get("User-Agent")

	// Insertar nuevo refresh token
	_, err = DB.Exec(context.Background(),
		`INSERT INTO refresh_tokens 
         (usuario_id, token, fecha_creacion, fecha_expiracion, revocado, direccion_ip, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		usuarioID,
		newRefresh,
		time.Now(),
		time.Now().Add(7*24*time.Hour),
		false,
		ip,
		userAgent,
	)

	if err != nil {
		log.Printf("Error al guardar nuevo refresh token: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al guardar sesión",
		})
	}

	return c.JSON(models.TokenPair{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
}

// Handler para logout
func Logout(c *fiber.Ctx) error {
	user := c.Locals("user").(*jwt.Token)

	claims, ok := user.Claims.(*models.Claims) // 👈 aquí es el cambio importante
	if !ok || !user.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token inválido",
		})
	}

	userID := claims.Subject // porque tu Claims tiene `jwt.RegisteredClaims`

	// Marcar token como revocado
	_, err := DB.Exec(context.Background(),
		`UPDATE refresh_tokens 
         SET revocado = true 
         WHERE usuario_id = $1 AND revocado = false`,
		userID,
	)

	if err != nil {
		log.Printf("Error al hacer logout: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al cerrar sesión",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Sesión cerrada correctamente",
	})
}

// Obtiene la información de un usuario por su ID
func Register(c *fiber.Ctx) error {
	var nuevo models.UsuarioRegistro

	if err := c.BodyParser(&nuevo); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	// Validación mínima
	if nuevo.Nombre == "" || nuevo.Correo == "" || nuevo.Password == "" || nuevo.Rol == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Faltan campos requeridos",
		})
	}

	// Verificar si el correo ya existe
	var existe int
	err := DB.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM usuarios WHERE correo=$1", nuevo.Correo).Scan(&existe)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error al verificar usuario"})
	}
	if existe > 0 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Ya existe un usuario con ese correo",
		})
	}

	// Hashear la contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(nuevo.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al encriptar la contraseña",
		})
	}

	// Insertar usuario en la base de datos
	query := `INSERT INTO usuarios (nombre, rol, correo, telefono, especialidad, password)
	          VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = DB.Exec(context.Background(), query,
		nuevo.Nombre, nuevo.Rol, nuevo.Correo, nuevo.Telefono, nuevo.Especialidad, string(hashedPassword))

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al registrar el usuario",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"mensaje": "Usuario registrado correctamente",
		"correo":  nuevo.Correo,
	})
}

// Obtiene la información de un usuario por su ID
func GetUsuario(c *fiber.Ctx) error {
	id := c.Params("id")

	// Definimos una estructura más completa para devolver todos los campos del usuario
	type UsuarioResponse struct {
		ID           int    `json:"id_usuario"`
		Nombre       string `json:"nombre"`
		Rol          string `json:"rol"`
		Correo       string `json:"correo"`
		Telefono     string `json:"telefono"`
		Especialidad string `json:"especialidad"`
	}

	var usuario UsuarioResponse

	// Consulta para obtener todos los campos del usuario excepto la contraseña
	query := `SELECT id_usuario, nombre, rol, correo, telefono, especialidad 
              FROM usuarios WHERE id_usuario=$1`

	err := DB.QueryRow(context.Background(), query, id).Scan(
		&usuario.ID,
		&usuario.Nombre,
		&usuario.Rol,
		&usuario.Correo,
		&usuario.Telefono,
		&usuario.Especialidad,
	)

	if err != nil {
		// Si no se encuentra el usuario, devolvemos un error 404
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Usuario no encontrado",
		})
	}

	return c.JSON(usuario)
}

// Obtiene la información de un usuario por su ID
func UpdateUsuario(c *fiber.Ctx) error {
	id := c.Params("id")

	var datos models.UsuarioRegistro
	if err := c.BodyParser(&datos); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	// Validación mínima
	if datos.Nombre == "" || datos.Rol == "" || datos.Correo == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Faltan campos requeridos",
		})
	}

	// Si se proporciona una nueva contraseña, hashearla
	var hashedPassword string
	if datos.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(datos.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "No se pudo encriptar la contraseña",
			})
		}
		hashedPassword = string(hash)
	}

	// Actualizar usuario
	query := `
		UPDATE usuarios
		SET nombre=$1, rol=$2, correo=$3, telefono=$4, especialidad=$5
		` + func() string {
		if hashedPassword != "" {
			return `, password=$6 WHERE id_usuario=$7`
		}
		return `WHERE id_usuario=$6`
	}()

	var err error
	if hashedPassword != "" {
		_, err = DB.Exec(context.Background(), query,
			datos.Nombre, datos.Rol, datos.Correo, datos.Telefono, datos.Especialidad, hashedPassword, id)
	} else {
		_, err = DB.Exec(context.Background(), query,
			datos.Nombre, datos.Rol, datos.Correo, datos.Telefono, datos.Especialidad, id)
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al actualizar usuario",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Usuario actualizado exitosamente",
	})
}

// Obtiene la información de un usuario por su ID
func DeleteUsuario(c *fiber.Ctx) error {
	id := c.Params("id")

	_, err := DB.Exec(context.Background(), "DELETE FROM usuarios WHERE id_usuario=$1", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al eliminar el usuario",
		})
	}

	return c.JSON(fiber.Map{
		"mensaje": "Usuario eliminado exitosamente",
	})
}

// Obtiene la información de un usuario por su ID
func LoginInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"mensaje": "Estás autenticado con exito",
	})
}

// Obtiene la información de un usuario por su ID
func Saludo(c *fiber.Ctx) error {
	return c.SendString("Hola mundo desde Fiber")
}
