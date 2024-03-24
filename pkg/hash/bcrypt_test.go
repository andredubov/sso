package hash_test

import (
	"errors"
	"math/rand"
	"testing"

	"github.com/andredubov/sso/pkg/hash"
	"github.com/dvln/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func randStringRunes(n int) string {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func TestBcryptHasher_HashAndSalt(t *testing.T) {
	bcryptHasher := hash.NewCryptoHasher(bcrypt.DefaultCost)
	plainPassword := "qwerty"

	hashedPassword, err := bcryptHasher.HashAndSalt(plainPassword)
	assert.Nil(t, err)

	err = bcryptHasher.ComparePasswords(hashedPassword, plainPassword)
	assert.Nil(t, err)
}

func TestBcryptHasher_HashAndSalt_Error(t *testing.T) {
	const plainPasswordMaxLength = 72
	bcryptHasher, length := hash.NewCryptoHasher(bcrypt.DefaultCost), plainPasswordMaxLength+1
	plainPassword := randStringRunes(length)

	_, err := bcryptHasher.HashAndSalt(plainPassword)

	assert.Equal(t, errors.Unwrap(err), bcrypt.ErrPasswordTooLong)
}

func TestBcryptHasher_ComparePasswords_Error(t *testing.T) {
	bcryptHasher := hash.NewCryptoHasher(bcrypt.DefaultCost)
	plainPassword, plainPassword2 := "qwerty", "qwerrty"

	hashedPassword, err := bcryptHasher.HashAndSalt(plainPassword2)
	assert.Nil(t, err)

	err = bcryptHasher.ComparePasswords(hashedPassword, plainPassword)
	assert.Equal(t, errors.Unwrap(err), bcrypt.ErrMismatchedHashAndPassword)
}
