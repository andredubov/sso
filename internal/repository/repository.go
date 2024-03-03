package repository

import (
	"context"
	"errors"

	"github.com/andredubov/sso/internal/domain/model"
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
	ErrAppExists    = errors.New("app already exists")
	ErrAppNotFound  = errors.New("app not found")
)

type Users interface {
	Add(ctx context.Context, user model.User) (string, error)
	GetByCredentials(ctx context.Context, email, password string) (model.User, error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
}

type Apps interface {
	Add(ctx context.Context, app model.App) (string, error)
	GetByID(ctx context.Context, appID string) (model.App, error)
}
