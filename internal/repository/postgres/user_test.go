package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/andredubov/sso/internal/domain/model"
	"github.com/dvln/testify/assert"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

func TestUser_Add(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	dbx := sqlx.NewDb(db, "sqlmock")
	usersRepository := NewUsersRepository(dbx)

	type test struct {
		name            string
		mockBehavior    func(model.User)
		input           model.User
		expectedUserID  string
		isExpectedError bool
	}

	const userID = "uuid"

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(user model.User) {
				rows := sqlmock.NewRows([]string{"id"}).AddRow(userID)
				query := fmt.Sprintf("INSERT INTO %s", usersTable)
				mock.ExpectQuery(query).WithArgs(user.Email, user.Password).WillReturnRows(rows)
			},
			input: model.User{
				Email:    "user's email",
				Password: "user's password",
			},
			expectedUserID:  userID,
			isExpectedError: false,
		},
		{
			name: "User already exsits",
			mockBehavior: func(user model.User) {
				query := fmt.Sprintf("INSERT INTO %s ", usersTable)
				errUniqueViolation := pq.Error{Code: "23505"}
				mock.ExpectQuery(query).WithArgs(user.Email, user.Password).WillReturnError(&errUniqueViolation)
			},
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(user model.User) {
				query := fmt.Sprintf("INSERT INTO %s", usersTable)
				mock.ExpectQuery(query).WithArgs(user.Email, user.Password).WillReturnError(fmt.Errorf("some error"))
			},
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.mockBehavior(test.input)

			actualUserID, err := usersRepository.Add(context.TODO(), test.input)
			if test.isExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedUserID, actualUserID)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestUser_GetByEmail(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	dbx := sqlx.NewDb(db, "sqlmock")
	usersRepository := NewUsersRepository(dbx)

	type test struct {
		name            string
		mockBehavior    func(string, model.User)
		input           string
		expected        model.User
		isExpectedError bool
	}

	email, password := "user's email", "user's password"

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(email string, user model.User) {
				rows := sqlmock.NewRows([]string{"id", "email", "password_hash", "is_admin"})
				rows.AddRow(user.ID, email, password, user.IsAdmin)
				query := fmt.Sprintf("SELECT (.+) FROM %s", usersTable)
				mock.ExpectQuery(query).WithArgs(email).WillReturnRows(rows)
			},
			input: email,
			expected: model.User{
				Email:    email,
				Password: password,
			},
			isExpectedError: false,
		},
		{
			name: "User not found error",
			mockBehavior: func(email string, user model.User) {
				query := fmt.Sprintf("SELECT (.+) FROM %s", usersTable)
				mock.ExpectQuery(query).WithArgs(email).WillReturnError(sql.ErrNoRows)
			},
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(email string, user model.User) {
				query := fmt.Sprintf("SELECT (.+) FROM %s", usersTable)
				mock.ExpectQuery(query).WithArgs(email).WillReturnError(fmt.Errorf("some error"))
			},
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.mockBehavior(test.input, test.expected)

			actual, err := usersRepository.GetByEmail(context.TODO(), test.input)
			if test.isExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, actual)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestUser_IsAdmin(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	dbx := sqlx.NewDb(db, "sqlmock")
	usersRepository := NewUsersRepository(dbx)

	type test struct {
		name            string
		mockBehavior    func(userID string)
		input           string
		expected        bool
		isExpectedError bool
	}

	userID, isUserAdmin := "uuid", true

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(userID string) {
				rows := sqlmock.NewRows([]string{"id", "email", "password_hash", "is_admin"})
				rows.AddRow(userID, "user@test.com", "passwordhash", isUserAdmin)
				query := fmt.Sprintf("SELECT (.+) FROM %s", usersTable)
				mock.ExpectQuery(query).WithArgs(userID).WillReturnRows(rows)
			},
			input:           userID,
			expected:        isUserAdmin,
			isExpectedError: false,
		},
		{
			name: "User not found error",
			mockBehavior: func(userID string) {
				query := fmt.Sprintf("SELECT (.+) FROM %s", usersTable)
				mock.ExpectQuery(query).WithArgs(userID).WillReturnError(sql.ErrNoRows)
			},
			isExpectedError: true,
		},
		{
			name: "Uknown error",
			mockBehavior: func(userID string) {
				query := fmt.Sprintf("SELECT (.+) FROM %s", usersTable)
				mock.ExpectQuery(query).WithArgs(userID).WillReturnError(fmt.Errorf("some error"))
			},
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.mockBehavior(test.input)

			actual, err := usersRepository.IsAdmin(context.TODO(), test.input)
			if test.isExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, actual)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
