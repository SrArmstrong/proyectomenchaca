package handlers

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

func SetDB(pool *pgxpool.Pool) {
	DB = pool
}

func GetDB() *pgxpool.Pool {
	return DB
}

func LogEvent(ctx context.Context, endpoint, metodo, usuario, mensaje, direccionIP, userAgent string) error {
	query := `
		INSERT INTO event_logs (endpoint, metodo, usuario, mensaje, direccion_ip, user_agent, fecha)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := DB.Exec(ctx, query, endpoint, metodo, usuario, mensaje, direccionIP, userAgent, time.Now())
	return err
}
