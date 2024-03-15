package auth

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/andredubov/sso/internal/domain/model"
	"github.com/dgrijalva/jwt-go"
)

//go:generate mockgen -source=manager.go -destination=mocks/mock.go

// TokenManager provides logic for JWT & Refresh tokens generation and parsing.
type TokenManager interface {
	NewJWT(user model.User, app model.App, ttl time.Duration) (string, error)
	Parse(accessToken string) (model.User, model.App, error)
	NewRefreshToken() (string, error)
}

type manager struct {
	signingKey string
}

// NewTokenManager create an instance of manager
func NewTokenManager(signingKey string) (TokenManager, error) {

	const op = "auth.NewTokenManager"

	if signingKey == "" {
		return nil, fmt.Errorf("%s: empty signing key", op)
	}

	return &manager{signingKey: signingKey}, nil
}

func (m *manager) NewJWT(user model.User, app model.App, ttl time.Duration) (string, error) {

	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(ttl).Unix()
	claims["user_id"] = user.ID
	claims["email"] = user.Email
	claims["app_id"] = app.ID

	return token.SignedString([]byte(m.signingKey))
}

func (m *manager) Parse(accessToken string) (model.User, model.App, error) {

	const op = "auth.tokenManager.Parse"

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (i interface{}, err error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%s: unexpected signing method: %v", op, token.Header["alg"])
		}

		return []byte(m.signingKey), nil
	})

	if err != nil {
		return model.User{}, model.App{}, fmt.Errorf("%s: %w", op, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return model.User{}, model.App{}, fmt.Errorf("%s: error get user claims from token", op)
	}

	user := model.User{ID: claims["user_id"].(string), Email: claims["email"].(string)}
	app := model.App{ID: claims["app_id"].(string)}

	return user, app, nil
}

func (m *manager) NewRefreshToken() (string, error) {

	const op = "auth.tokenManager.Parse"

	b := make([]byte, 32)
	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)

	if _, err := r.Read(b); err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return fmt.Sprintf("%x", b), nil
}
