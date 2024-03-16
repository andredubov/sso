package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
)

var (
	ErrAppExists = errors.New("application already exists")
)

type appCreator struct {
	appsRepository repository.Apps
}

// NewAppCreater returns a new instance app creator service
func NewAppCreator(appsRepo repository.Apps) AppCreator {
	return &appCreator{
		appsRepository: appsRepo,
	}
}

// Create registers a new application in the system and returns application ID
// If application with given name already exists return error
func (a *appCreator) Create(ctx context.Context, name, secret string) (string, error) {

	const op = "appCreator.Create"

	id, err := a.appsRepository.Add(ctx, model.App{Name: name, Secret: secret})
	if err != nil {
		if errors.Is(err, repository.ErrAppExists) {
			return "", fmt.Errorf("%s: %w", op, ErrAppExists)
		}
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}
