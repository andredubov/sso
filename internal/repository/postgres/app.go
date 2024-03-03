package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
	"github.com/jmoiron/sqlx"
	"github.com/omeid/pgerror"
)

const (
	appsTable = "apps"
)

type appsRepository struct {
	db *sqlx.DB
}

// NewAppsRepository create an instance of the appsRepository
func NewAppsRepository(db *sqlx.DB) *appsRepository {
	return &appsRepository{
		db: db,
	}
}

// Add a new application to the repository
func (a *appsRepository) Add(ctx context.Context, app model.App) (string, error) {

	const op = "postgres.appsRepository.Add"

	var id string
	query := fmt.Sprintf("INSERT INTO %s (name, secret) VALUES ($1, $2) RETURNING id", appsTable)

	row := a.db.QueryRow(query, app.Name, app.Secret)
	if err := row.Scan(&id); err != nil {

		if e := pgerror.UniqueViolation(err); e != nil {
			return "", fmt.Errorf("%s: %w", op, repository.ErrAppExists)
		}
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// GetById fetch an application from the repository
func (a *appsRepository) GetByID(ctx context.Context, appID string) (model.App, error) {

	const op = "postgres.appsRepository.GetById"

	var app model.App
	query := fmt.Sprintf("SELECT * FROM %s WHERE id=$1", appsTable)

	if err := a.db.Get(&app, query, appID); err != nil {

		if errors.Is(err, sql.ErrNoRows) {
			return model.App{}, fmt.Errorf("%s: %w", op, repository.ErrAppNotFound)
		}
		return model.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
