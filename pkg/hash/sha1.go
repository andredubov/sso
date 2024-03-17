package hash

import (
	"crypto/sha1"
	"fmt"
)

// sha1Hasher uses SHA1 to hash passwords with provided salt.
type sha1Hasher struct {
	salt string
}

// NewSHA1Hasher returns an instance of sha1 hasher.
func NewSHA1Hasher(salt string) PasswordHasher {
	return &sha1Hasher{salt: salt}
}

// HashAndSalt returns the sha1 hash of the password at the given salt.
func (h *sha1Hasher) HashAndSalt(password string) (string, error) {

	const op = "sha1Hasher.HashAndSalt"

	hash := sha1.New()

	if _, err := hash.Write([]byte(password)); err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return fmt.Sprintf("%x", hash.Sum([]byte(h.salt))), nil
}

// ComparePasswords compares a bcrypt hashed password with its possible plaintext equivalent. Returns nil on success, or an error on failure.
func (h *sha1Hasher) ComparePasswords(hashedPassword string, plainPassword string) error {

	const op = "sha1Hasher.ComparePasswords"

	passwordHash, err := h.HashAndSalt(plainPassword)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if passwordHash != hashedPassword {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
