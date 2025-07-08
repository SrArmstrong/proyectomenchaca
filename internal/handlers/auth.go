package handlers

import (
	"context"
	"fmt"
	"log"
	"proyectomenchaca/internal/models"
	"proyectomenchaca/internal/utils"
	"regexp"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// Obtiene la información de un usuario por su ID
func Login(c *fiber.Ctx) error {
	inicio := time.Now()

	var datos models.UsuarioLogin
	if err := c.BodyParser(&datos); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"Int_Code":   "F",
			"StatusCode": fiber.StatusBadRequest,
			"Data": []map[string]interface{}{
				{
					"mensaje":          "Datos inválidos",
					"timestamp":        time.Now().Format(time.RFC3339),
					"tiempo_respuesta": time.Since(inicio).String(),
				},
			},
		})
	}

	/* Función para ver los datos que se reciben
	jsonBytes, err := json.MarshalIndent(datos, "", "  ")
	if err != nil {
		log.Println("Error al serializar datos:", err)
	} else {
		log.Println("Datos recibidos en login:", string(jsonBytes))
	}
	*/

	ip := c.IP()
	userAgent := c.Get("User-Agent")

	var usuario models.UsuarioBD
	err := DB.QueryRow(context.Background(),
		//err = DB.QueryRow(context.Background(), Cambiar en caso de verificar datos recibidos
		`SELECT id_usuario, nombre, password, rol, secret_totp 
         FROM usuarios WHERE correo = $1`, datos.Correo).Scan(
		&usuario.ID, &usuario.Nombre, &usuario.Password, &usuario.Rol, &usuario.SecretTOTP)

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"Int_Code":   "F",
			"StatusCode": fiber.StatusUnauthorized,
			"Data": []map[string]interface{}{
				{
					"mensaje":          "Credenciales inválidas",
					"timestamp":        time.Now().Format(time.RFC3339),
					"tiempo_respuesta": time.Since(inicio).String(),
				},
			},
		})
	}

	valid, err := totp.ValidateCustom(datos.CodigoTOTP, usuario.SecretTOTP, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      2,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"Int_Code":   "E",
			"StatusCode": fiber.StatusInternalServerError,
			"Data": []map[string]interface{}{
				{
					"mensaje":          "Error validando código TOTP",
					"timestamp":        time.Now().Format(time.RFC3339),
					"tiempo_respuesta": time.Since(inicio).String(),
				},
			},
		})
	}

	if !valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"Int_Code":   "F",
			"StatusCode": fiber.StatusUnauthorized,
			"Data": []map[string]interface{}{
				{
					"mensaje":          "Código TOTP inválido",
					"timestamp":        time.Now().Format(time.RFC3339),
					"tiempo_respuesta": time.Since(inicio).String(),
				},
			},
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(usuario.Password), []byte(datos.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"Int_Code":   "F",
			"StatusCode": fiber.StatusUnauthorized,
			"Data": []map[string]interface{}{
				{
					"mensaje":          "Credenciales inválidas",
					"timestamp":        time.Now().Format(time.RFC3339),
					"tiempo_respuesta": time.Since(inicio).String(),
				},
			},
		})
	}

	accessToken, refreshToken, err := utils.CrearTokens(usuario.ID, usuario.Nombre, usuario.Rol)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"Int_Code":   "E",
			"StatusCode": fiber.StatusInternalServerError,
			"Data": []map[string]interface{}{
				{
					"mensaje":          "Error generando tokens",
					"timestamp":        time.Now().Format(time.RFC3339),
					"tiempo_respuesta": time.Since(inicio).String(),
				},
			},
		})
	}

	_, err = DB.Exec(context.Background(),
		`INSERT INTO refresh_tokens (usuario_id, token, fecha_creacion, fecha_expiracion, revocado, direccion_ip, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		usuario.ID, refreshToken, time.Now(), time.Now().Add(7*24*time.Hour), false, ip, userAgent)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"Int_Code":   "E",
			"StatusCode": fiber.StatusInternalServerError,
			"Data": []map[string]interface{}{
				{
					"mensaje":          "Error al guardar sesión",
					"timestamp":        time.Now().Format(time.RFC3339),
					"tiempo_respuesta": time.Since(inicio).String(),
				},
			},
		})
	}

	// Éxito
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"Int_Code":   "S",
		"StatusCode": fiber.StatusOK,
		"Data": []map[string]interface{}{
			{
				"mensaje":          "Inicio de sesión exitoso",
				"timestamp":        time.Now().Format(time.RFC3339),
				"tiempo_respuesta": time.Since(inicio).String(),
			},
		},
		"access_token":  accessToken,
		"refresh_token": refreshToken,
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

// Verifica la seguridad de la contraseña
func isStrongPassword(password string) bool {
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[@$!%*#?&]`).MatchString(password)
	longEnough := len(password) >= 12

	return hasUpper && hasLower && hasNumber && hasSpecial && longEnough
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
	if err != nil || existe > 0 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Usuario ya existe"})
	}

	// Generar secreto TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MiAppSegura",
		AccountName: nuevo.Correo,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "No se pudo generar el TOTP",
		})
	}
	secret := key.Secret()

	if !isStrongPassword(nuevo.Password) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "La contraseña debe tener al menos 12 caracteres, incluyendo mayúsculas, minúsculas, números y símbolos.",
		})
	}

	// Hashear la contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(nuevo.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al encriptar contraseña",
		})
	}

	// Insertar usuario
	query := `INSERT INTO usuarios (nombre, rol, correo, telefono, especialidad, password, secret_totp)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = DB.Exec(context.Background(), query,
		nuevo.Nombre, nuevo.Rol, nuevo.Correo, nuevo.Telefono, nuevo.Especialidad, string(hashedPassword), secret)

	if err != nil {
		fmt.Println("Error SQL:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error al registrar el usuario",
		})
	}

	// Regresar la URL para escanear con la app de autenticación
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"mensaje":     "Usuario registrado correctamente",
		"correo":      nuevo.Correo,
		"secret":      secret,
		"otpauth_url": key.URL(), // Puedes generar el QR con esta URL si luego agregas interfaz
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

	// Obtener usuario que hace la petición, si tienes JWT puedes hacer algo como:
	var usuarioPeticion string
	if u := c.Locals("user"); u != nil {
		// Asumiendo que el user en Locals es un struct o mapa con email o nombre
		// Ajusta según tu implementación real
		if userMap, ok := u.(map[string]interface{}); ok {
			if email, ok := userMap["email"].(string); ok {
				usuarioPeticion = email
			}
		} else if userStr, ok := u.(string); ok {
			usuarioPeticion = userStr
		}
	}

	// Crear mensaje personalizado
	mensaje := ""
	if err != nil {
		// Loguear que no se encontró usuario
		mensaje = "Usuario no encontrado con ID " + id

		// Guardar log (usa go routine para no bloquear)
		go func() {
			_ = LogEvent(c.Context(), "/usuarios/"+id, "GET", usuarioPeticion, mensaje, c.IP(), c.Get("User-Agent"))
		}()

		// Responder error 404
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Usuario no encontrado",
		})
	}

	// Loguear acceso exitoso
	mensaje = "Consulta exitosa para usuario con ID " + id
	go func() {
		_ = LogEvent(c.Context(), "/usuarios/"+id, "GET", usuarioPeticion, mensaje, c.IP(), c.Get("User-Agent"))
	}()

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
