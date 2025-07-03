package main

import (
	"context"
	"log"
	"os"
	"proyectomenchaca/internal/handlers"
	"proyectomenchaca/internal/middleware"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	// ====================== Cargar variables de entorno ======================
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error al cargar el archivo .env")
	}

	// ====================== Conexión a Supabase PostgreSQL ======================
	dbUser := os.Getenv("user")
	dbPass := os.Getenv("password")
	dbHost := os.Getenv("host")
	dbPort := os.Getenv("port")
	dbName := os.Getenv("dbname")

	connString := "postgres://" + dbUser + ":" + dbPass + "@" + dbHost + ":" + dbPort + "/" + dbName + "?sslmode=require"

	// Configurar el pool de conexiones (recomendado para Supabase)
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		log.Fatalf("Error al configurar la conexión: %v", err)
	}

	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	// Configuración para Supabase
	config.MaxConns = 5                       // Límite para el plan gratuito
	config.MinConns = 1                       // Conexiones mínimas
	config.MaxConnIdleTime = 30 * time.Second // Cierra conexiones inactivas rápidamente
	config.MaxConnLifetime = 10 * time.Minute // Recicla conexiones periódicamente
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET statement_timeout = 30000")
		return err
	}

	// Conectar con reintentos
	var pool *pgxpool.Pool
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pool, err = pgxpool.NewWithConfig(ctx, config)
		cancel()

		if err == nil {
			break
		}

		log.Printf("Intento %d fallido: %v", i+1, err)
		if i < 2 {
			time.Sleep(2 * time.Second)
		}
	}

	if err != nil {
		log.Fatalf("No se pudo conectar a Supabase: %v", err)
	}
	defer pool.Close()

	handlers.SetDB(pool)

	// Verificar conexión
	var version string
	if err := pool.QueryRow(context.Background(), "SELECT version()").Scan(&version); err != nil {
		log.Fatalf("Error al verificar la conexión: %v", err)
	}
	log.Println("Conectado a Supabase PostgreSQL:", version)

	// ====================== Configuración de Fiber ======================
	app := fiber.New()

	// Middlewares
	app.Use(middleware.Logger())

	app.Use(middleware.Logger())

	app.Use(limiter.New(limiter.Config{
		Max:        100,             //
		Expiration: 1 * time.Minute, //
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Demasiadas solicitudes, intenta nuevamente más tarde.",
			})
		},
	}))

	// Rutas públicas
	app.Post("/register", handlers.Register)    // Registrar usuario
	app.Post("/login", handlers.Login)          // Logear usuario
	app.Post("/refresh", handlers.RefreshToken) // Refrescar token
	app.Get("/consultorios", handlers.GetConsultoriosDisponibles)
	app.Get("/horarios", handlers.GetHorariosDisponibles)

	// Grupo de rutas protegidas (requieren JWT)
	api := app.Group("/api", middleware.JWTProtected())

	// Ruta de logout
	api.Post("/logout", handlers.Logout)

	// Grupo de rutas accesibles solo para el admin
	admin := api.Group("", middleware.OnlyAdmin())

	// Grupo de rutas accesibles para médicos y admin
	medico := api.Group("", middleware.OnlyMedicoOrAdmin())

	// Rutas de usuarios (solo admin puede ver o editar usuarios)
	admin.Get("/usuarios/:id", handlers.GetUsuario)
	admin.Put("/usuarios/:id", handlers.UpdateUsuario)
	admin.Delete("/usuarios/:id", handlers.DeleteUsuario)

	// Rutas de expedientes (solo medico puede ver o editar usuarios)
	medico.Post("/expedientes", handlers.CreateExpediente)
	medico.Put("/expedientes/:id", handlers.UpdateExpediente)
	medico.Delete("/expedientes/:id", handlers.DeleteExpediente)

	// Rutas de expedientes que podría acceder un paciente solo para sí mismo
	api.Get("/expedientes/:id", handlers.GetExpediente) // Aquí en handler valida que el ID sea del propio usuario si es paciente

	// Rutas de consultorios (solo admin o médicos)
	medico.Post("/consultorios", handlers.CreateConsultorio)
	medico.Get("/consultorios/:id", handlers.GetConsultorio)
	medico.Put("/consultorios/:id", handlers.UpdateConsultorio)
	medico.Delete("/consultorios/:id", handlers.DeleteConsultorio)

	// Rutas de consultas
	medico.Post("/consultas", handlers.CreateConsulta)
	medico.Put("/consultas/:id", handlers.UpdateConsulta)
	medico.Delete("/consultas/:id", handlers.DeleteConsulta)
	medico.Get("/consultas/:id", handlers.GetConsulta) // El médico o el paciente pueden consultar, puede validarse en handler

	// Rutas de horarios
	medico.Post("/horarios", handlers.CreateHorario)
	medico.Put("/horarios/:id", handlers.UpdateHorario)
	medico.Delete("/horarios/:id", handlers.DeleteHorario)
	medico.Get("/horarios/:id", handlers.GetHorario)

	// Rutas de recetas
	medico.Post("/recetas", handlers.CreateReceta)
	medico.Put("/recetas/:id", handlers.UpdateReceta)
	medico.Delete("/recetas/:id", handlers.DeleteReceta)
	medico.Get("/recetas/:id", handlers.GetReceta)

	// Ruta de prueba
	api.Get("/saludo", middleware.OnlyAdmin(), handlers.Saludo)

	// Iniciar servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(app.Listen(":" + port))
}
