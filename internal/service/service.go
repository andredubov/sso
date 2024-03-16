package service

import (
	"context"

	"github.com/andredubov/sso/internal/domain/model"
)

type Auth interface {
	SignUp(ctx context.Context, user model.User) (string, error)
	SignIn(ctx context.Context, email, password, appID string) (string, error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
}

type AppCreator interface {
	Create(ctx context.Context, name, secret string) (string, error)
}
