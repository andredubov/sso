package hash_test

import (
	"testing"

	"github.com/andredubov/sso/pkg/hash"
	"github.com/dvln/testify/assert"
)

func TestSHA1_HashAndSalt(t *testing.T) {
	salt, plainPassword := "some salt", "qwerty"
	sha1Hasher := hash.NewSHA1Hasher(salt)

	actual, err := sha1Hasher.HashAndSalt(plainPassword)
	expected := "736f6d652073616c74b1b3773a05c0ed0176787a4f1574ff0075f7521e"

	assert.Nil(t, err)
	assert.Equal(t, actual, expected)
}

func TestSHA1_ComparePasswords(t *testing.T) {
	salt, plainPassword := "some salt", "qwerty"
	hashedPassword := "736f6d652073616c74b1b3773a05c0ed0176787a4f1574ff0075f7521e"
	sha1Hasher := hash.NewSHA1Hasher(salt)

	err := sha1Hasher.ComparePasswords(hashedPassword, plainPassword)

	assert.Nil(t, err)
}

func TestSHA1_ComparePasswords_Error(t *testing.T) {
	salt, plainPassword := "some salt", "qwerty"
	hashedPassword := "736f6d652073616c74b1b3773a05c0ed0176787a4f1574ff0075f7521f"
	sha1Hasher := hash.NewSHA1Hasher(salt)

	err := sha1Hasher.ComparePasswords(hashedPassword, plainPassword)

	assert.NotNil(t, err)
}
