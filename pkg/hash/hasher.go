package hash

//go:generate mockgen -source=hasher.go -destination=mocks/mock.go

// PasswordHasher provides hashing logic to securely store passwords.
type PasswordHasher interface {
	HashAndSalt(plainPassword string) (string, error)
	ComparePasswords(hashedPassword string, plainPassword string) error
}
