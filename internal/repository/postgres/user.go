package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
	"github.com/jmoiron/sqlx"
	"github.com/omeid/pgerror"
)

const (
	usersTable = "users"
)

type usersRepository struct {
	db *sqlx.DB
}

// NewUsersRepository create an instance of the usersRepository
func NewUsersRepository(db *sqlx.DB) repository.Users {
	return &usersRepository{
		db: db,
	}
}

// Add a new user to the repository
func (u *usersRepository) Add(ctx context.Context, user model.User) (string, error) {

	const op = "postgres.userRepository.Add"

	var id string
	query := fmt.Sprintf("INSERT INTO %s (email, password_hash) VALUES ($1, $2) RETURNING id", usersTable)

	row := u.db.QueryRow(query, user.Email, user.Password)
	if err := row.Scan(&id); err != nil {

		if e := pgerror.UniqueViolation(err); e != nil {
			return "", fmt.Errorf("%s: %w", op, repository.ErrUserExists)
		}
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// GetByCredentials fetch a user by its email from the repository
func (u *usersRepository) GetByEmail(ctx context.Context, email string) (model.User, error) {

	const op = "postgres.userRepository.GetByEmail"

	var user model.User
	query := fmt.Sprintf("SELECT * FROM %s WHERE email=$1", usersTable)

	if err := u.db.Get(&user, query, email); err != nil {

		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, fmt.Errorf("%s: %w", op, repository.ErrUserNotFound)
		}
		return model.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

// IsAdmin found out weather the user is an admin or no
func (u *usersRepository) IsAdmin(ctx context.Context, userID string) (bool, error) {

	const op = "postgres.userRepository.IsAdmin"

	var user model.User
	query := fmt.Sprintf("SELECT is_admin FROM %s WHERE id=$1", usersTable)

	if err := u.db.Get(&user, query, userID); err != nil {

		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, repository.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return user.IsAdmin, nil
}
