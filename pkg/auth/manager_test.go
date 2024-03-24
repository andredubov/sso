package auth_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/pkg/auth"
	"github.com/dvln/testify/assert"
)

func TestNewTokenManager(t *testing.T) {
	signingKey := "sign key"
	userExpected, appExpected, ttl := model.User{Email: "user@gmail.com"}, model.App{ID: "appID"}, 5*time.Minute

	tokenManager, err := auth.NewTokenManager(signingKey)
	assert.Nil(t, err)

	token, err := tokenManager.NewJWT(userExpected, appExpected, ttl)
	assert.Nil(t, err)

	userActual, appActual, err := tokenManager.Parse(token)

	assert.Equal(t, userActual, userExpected)
	assert.Equal(t, appActual, appExpected)
	assert.Nil(t, err)
}

func TestNewTokenManager_EmptySignKeyError(t *testing.T) {
	signingKey := ""
	_, err := auth.NewTokenManager(signingKey)
	assert.Equal(t, err, errors.New("auth.NewTokenManager: empty signing key"))
}

func TestNewTokenManager_TokenParseError(t *testing.T) {
	signingKey := "sign key"
	userExpected, appExpected, ttl := model.User{Email: "user@gmail.com"}, model.App{ID: "appID"}, 5*time.Minute

	tokenManager, err := auth.NewTokenManager(signingKey)
	assert.Nil(t, err)

	token, err := tokenManager.NewJWT(userExpected, appExpected, ttl)
	assert.Nil(t, err)

	token = strings.Replace(token, ".", "-", 1)

	_, _, err = tokenManager.Parse(token)

	assert.NotNil(t, err)
}
