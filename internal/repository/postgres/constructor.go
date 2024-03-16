package postgres

import (
	"github.com/andredubov/sso/internal/repository"
	"github.com/jmoiron/sqlx"
)

// NewRepository returns a new instance of the repository.Repository struct
func NewRepository(db *sqlx.DB) *repository.Repository {
	return &repository.Repository{
		Users: NewUsersRepository(db),
		Apps:  NewAppsRepository(db),
	}
}
