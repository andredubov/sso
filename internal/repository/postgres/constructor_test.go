package postgres

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dvln/testify/assert"
	"github.com/jmoiron/sqlx"
)

func TestConstructor_NewRepository(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	dbx := sqlx.NewDb(db, "sqlmock")
	usersRepository, appsRepository := NewUsersRepository(dbx), NewAppsRepository(dbx)
	repo := NewRepository(dbx)

	assert.Equal(t, repo.Users, usersRepository)
	assert.Equal(t, repo.Apps, appsRepository)

	assert.NoError(t, mock.ExpectationsWereMet())
}
