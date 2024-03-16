package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/andredubov/sso/internal/config"
	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
	"github.com/andredubov/sso/pkg/auth"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type authService struct {
	repository   *repository.Repository
	tokenManager auth.TokenManager
	jwtConfig    config.JWT
}

// New returns a new instance of the auth service
func NewAuthService(repo *repository.Repository, manager auth.TokenManager, cfg config.JWT) Auth {
	return &authService{
		repository:   repo,
		tokenManager: manager,
		jwtConfig:    cfg,
	}
}

// SignUp registers a new user in the system and returns user ID
// If user with given email already exists return error
func (a *authService) SignUp(ctx context.Context, user model.User) (string, error) {

	const op = "authService.SignUp"

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	user.Password = string(passwordHash)

	return a.repository.Users.Add(ctx, user)
}

// SignIn checks if a user with given credentials exists in the system
// If user exists, but password incorrect returns error
// If user doesn't exist returns error
func (a *authService) SignIn(ctx context.Context, email, password, appID string) (string, error) {

	const op = "authService.SignIn"

	user, err := a.repository.Users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.repository.Apps.GetByID(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := a.tokenManager.NewJWT(user, app, a.jwtConfig.AccessTokenTTL)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, err
}

// IsAdmin checks if a user is admin
func (a *authService) IsAdmin(ctx context.Context, userID string) (bool, error) {

	const op = "authService.IsAdmin"

	isAdmin, err := a.repository.Users.IsAdmin(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}
