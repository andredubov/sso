package auth

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//go:generate mockgen -source=manager.go -destination=mocks/mock.go

// TokenManager provides logic for JWT & Refresh tokens generation and parsing.
type TokenManager interface {
	NewJWT(userId string, ttl time.Duration) (string, error)
	Parse(accessToken string) (string, error)
	NewRefreshToken() (string, error)
}

type manager struct {
	signingKey string
}

func NewTokenManager(signingKey string) (*manager, error) {

	const op = "auth.NewTokenManager.Parse"

	if signingKey == "" {
		return nil, fmt.Errorf("%s: empty signing key", op)
	}

	return &manager{signingKey: signingKey}, nil
}

func (m *manager) NewJWT(userId string, ttl time.Duration) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Subject:   userId,
	})

	return token.SignedString([]byte(m.signingKey))
}

func (m *manager) Parse(accessToken string) (string, error) {

	const op = "auth.TokenManager.Parse"

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (i interface{}, err error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%s: unexpected signing method: %v", op, token.Header["alg"])
		}

		return []byte(m.signingKey), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("%s: error get user claims from token", op)
	}

	return claims["sub"].(string), nil
}

func (m *manager) NewRefreshToken() (string, error) {

	b := make([]byte, 32)
	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)

	if _, err := r.Read(b); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}
