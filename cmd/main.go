package main

import (
	"context"
	"log"
	"os"
	"proyectomenchaca/internal/handlers"
	"proyectomenchaca/internal/middleware"
	"time"

	"github.com/gofiber/fiber/v2"
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

	// Configuración recomendada para Supabase
	config.MaxConns = 5 // Límite para el plan gratuito
	config.MinConns = 1 // Conexiones mínimas
	config.HealthCheckPeriod = 1 * time.Minute
	config.MaxConnLifetime = 30 * time.Minute
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

	// Rutas públicas
	app.Get("/hola", handlers.Saludo)
	app.Post("/register", handlers.Register)
	app.Post("/login", handlers.Login)

	// Rutas protegidas (requieren JWT)
	app.Get("/info_system", middleware.JWTProtected(), handlers.SystemInfo)
	app.Get("/login", middleware.JWTProtected(), handlers.LoginInfo)

	// Iniciar servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(app.Listen(":" + port))
}
