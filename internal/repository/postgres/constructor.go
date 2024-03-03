package postgres

import (
	"github.com/andredubov/sso/internal/repository"
	"github.com/jmoiron/sqlx"
)

type repo struct {
	Users repository.Users
	Apps  repository.Apps
}

func NewRepository(db *sqlx.DB) *repo {
	return &repo{
		Users: NewUsersRepository(db),
		Apps:  NewAppsRepository(db),
	}
}
