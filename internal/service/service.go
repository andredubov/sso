package service

import (
	"context"

	"github.com/andredubov/sso/internal/config"
	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
	"github.com/andredubov/sso/pkg/auth"
)

type Auth interface {
	SignUp(ctx context.Context, user model.User) (string, error)
	SignIn(ctx context.Context, email, password, appID string) (string, error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
}

type AppCreator interface {
	Create(ctx context.Context, name, secret string) (string, error)
}

type Service struct {
	Auth       Auth
	AppCreator AppCreator
}

func New(repo *repository.Repository, manager auth.TokenManager, cfg config.JWTConfig) *Service {
	return &Service{
		Auth:       NewAuthService(repo, manager, cfg),
		AppCreator: NewAppCreator(repo.Apps),
	}
}
