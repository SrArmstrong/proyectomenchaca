package main

import (
	"context"
	"log"
	"os"
	"proyectomenchaca/internal/handlers"
	"proyectomenchaca/internal/middleware"
	"time"

	"github.com/gofiber/fiber/v2/middleware/cors"

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

	// Habilita CORS para todas las rutas y orígenes
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:4200", // origen del frontend
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
	}))

	// Middlewares
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
	//admin := api.Group("", middleware.OnlyAdmin())

	// Grupo de rutas accesibles para médicos y admin
	//medico := api.Group("", middleware.OnlyMedicoOrAdmin())

	// Rutas de usuarios
	api.Get("/usuarios/:id", middleware.HasPermission("read_usuario"), handlers.GetUsuario)
	api.Put("/usuarios/:id", middleware.HasPermission("update_usuario"), handlers.UpdateUsuario)
	api.Delete("/usuarios/:id", middleware.HasPermission("delete_usuario"), handlers.DeleteUsuario)

	// Rutas de expedientes
	api.Post("/expedientes", middleware.HasPermission("add_expediente"), handlers.CreateExpediente)
	api.Put("/expedientes/:id", middleware.HasPermission("update_expediente"), handlers.UpdateExpediente)
	api.Delete("/expedientes/:id", middleware.HasPermission("delete_expediente"), handlers.DeleteExpediente)
	api.Get("/expedientes/:id", middleware.HasPermission("read_expediente"), handlers.GetExpediente)
	api.Get("/expedientes", middleware.HasPermission("read_expediente"), handlers.GetAllExpedientes)

	// Rutas de consultorios
	api.Post("/consultorios", middleware.HasPermission("add_consultorio"), handlers.CreateConsultorio)
	api.Get("/consultorios", middleware.HasPermission("read_consultorio"), handlers.GetConsultoriosDisponibles) // Nueva ruta
	api.Get("/consultorios/:id", middleware.HasPermission("read_consultorio"), handlers.GetConsultorio)
	api.Put("/consultorios/:id", middleware.HasPermission("update_consultorio"), handlers.UpdateConsultorio)
	api.Delete("/consultorios/:id", middleware.HasPermission("delete_consultorio"), handlers.DeleteConsultorio)

	// Rutas de consultas
	api.Post("/consultas", middleware.HasPermission("add_consulta"), handlers.CreateConsulta)
	api.Put("/consultas/:id", middleware.HasPermission("update_consulta"), handlers.UpdateConsulta)
	api.Delete("/consultas/:id", middleware.HasPermission("delete_consulta"), handlers.DeleteConsulta)
	api.Get("/consultas/:id", middleware.HasPermission("read_consulta"), handlers.GetConsulta)
	api.Get("/consultas", middleware.HasPermission("read_consulta"), handlers.GetAllConsultas)

	// Rutas de horarios
	api.Post("/horarios", middleware.HasPermission("add_horario"), handlers.CreateHorario)
	api.Put("/horarios/:id", middleware.HasPermission("update_horario"), handlers.UpdateHorario)
	api.Delete("/horarios/:id", middleware.HasPermission("delete_horario"), handlers.DeleteHorario)
	api.Get("/horarios/:id", middleware.HasPermission("read_horario"), handlers.GetHorario)

	// Rutas de recetas
	api.Post("/recetas", middleware.HasPermission("add_receta"), handlers.CreateReceta)
	api.Put("/recetas/:id", middleware.HasPermission("update_receta"), handlers.UpdateReceta)
	api.Delete("/recetas/:id", middleware.HasPermission("delete_receta"), handlers.DeleteReceta)
	api.Get("/recetas/:id", middleware.HasPermission("read_receta"), handlers.GetReceta)
	api.Get("/recetas", middleware.HasPermission("read_receta"), handlers.GetAllRecetas)

	// Ruta de prueba
	api.Get("/saludo", middleware.HasPermission("read_usuario"), handlers.Saludo)

	// Iniciar servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(app.Listen(":" + port))
}
