package database

import (
	"fmt"

	"github.com/andredubov/sso/internal/config"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// NewPostgresConnection open a connection to the postgres
func NewPostgresConnection(cfg *config.Config) (*sqlx.DB, error) {

	db, err := sqlx.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=%s password=%s",
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.Username,
		cfg.Postgres.DatabaseName,
		cfg.Postgres.SSLMode,
		cfg.Postgres.Password))

	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
