package database

import (
	"fmt"

	"github.com/andredubov/sso/internal/config"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// NewPostgresConnection creates a connection to the postgres
func NewPostgresConnection(cfg *config.Postgres) (*sqlx.DB, error) {

	db, err := sqlx.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=%s password=%s",
		cfg.Host,
		cfg.Port,
		cfg.Username,
		cfg.DatabaseName,
		cfg.SSLMode,
		cfg.Password))

	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
