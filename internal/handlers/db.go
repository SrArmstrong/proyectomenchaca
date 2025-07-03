package handlers

import "github.com/jackc/pgx/v5/pgxpool"

var DB *pgxpool.Pool

func SetDB(pool *pgxpool.Pool) {
	DB = pool
}

func GetDB() *pgxpool.Pool {
	return DB
}
