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

//go:generate mockgen -source=repository.go -destination=mocks/mock.go

// Users users repository interface
type Users interface {
	Add(ctx context.Context, user model.User) (string, error)
	GetByEmail(ctx context.Context, email string) (model.User, error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
}

// Apps apps repository interface
type Apps interface {
	Add(ctx context.Context, app model.App) (string, error)
	GetByID(ctx context.Context, appID string) (model.App, error)
}

// Repository repository entity
type Repository struct {
	Users Users
	Apps  Apps
}
