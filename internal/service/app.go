package service

import (
	"context"

	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
)

type appsCreator struct {
	appsRepository repository.Apps
}

// NewAppCreater
func NewAppCreator(appsRepo repository.Apps) AppCreator {
	return &appsCreator{
		appsRepository: appsRepo,
	}
}

func (a *appsCreator) Create(ctx context.Context, name, secret string) (string, error) {

	return a.appsRepository.Add(ctx, model.App{Name: name, Secret: secret})
}
