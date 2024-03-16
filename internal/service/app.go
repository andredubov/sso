package service

import (
	"context"

	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
)

type appsCreator struct {
	appsRepository repository.Apps
}

// NewAppCreater returns a new instance app creator service
func NewAppCreator(appsRepo repository.Apps) AppCreator {
	return &appsCreator{
		appsRepository: appsRepo,
	}
}

// Create registers a new application in the system and returns application ID
// If application with given name already exists return error
func (a *appsCreator) Create(ctx context.Context, name, secret string) (string, error) {

	return a.appsRepository.Add(ctx, model.App{Name: name, Secret: secret})
}
