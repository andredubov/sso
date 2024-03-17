package hash

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type bcyptHasher struct {
	cost int
}

// NewCryptoHasher returns an instance of bcypt hasher.
func NewCryptoHasher(cost int) PasswordHasher {
	return &bcyptHasher{
		cost: cost,
	}
}

// HashAndSalt returns the bcrypt hash of the password at the given cost.
func (h *bcyptHasher) HashAndSalt(plainPassword string) (string, error) {

	const op = "bcyptHasher.HashAndSalt"

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plainPassword), h.cost)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return string(hashedPassword), nil
}

// ComparePasswords compares a bcrypt hashed password with its possible plaintext equivalent. Returns nil on success, or an error on failure.
func (h *bcyptHasher) ComparePasswords(hashedPassword string, plainPassword string) error {

	const op = "bcyptHasher.ComparePasswords"

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
