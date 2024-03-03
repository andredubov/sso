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

func TestApp_Add(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	dbx := sqlx.NewDb(db, "sqlmock")
	appsRepository := NewAppsRepository(dbx)

	type test struct {
		name            string
		mockBehavior    func(model.App)
		input           model.App
		expectedAppID   string
		isExpectedError bool
	}

	const appID = "uuid"

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(app model.App) {
				rows := sqlmock.NewRows([]string{"id"}).AddRow(appID)
				query := fmt.Sprintf("INSERT INTO %s", appsTable)
				mock.ExpectQuery(query).WithArgs(app.Name, app.Secret).WillReturnRows(rows)
			},
			input: model.App{
				Name:   "app's name",
				Secret: "app's secret",
			},
			expectedAppID:   appID,
			isExpectedError: false,
		},
		{
			name: "User already exsits",
			mockBehavior: func(app model.App) {
				query := fmt.Sprintf("INSERT INTO %s ", appsTable)
				errUniqueViolation := pq.Error{Code: "23505"}
				mock.ExpectQuery(query).WithArgs(app.Name, app.Secret).WillReturnError(&errUniqueViolation)
			},
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(app model.App) {
				query := fmt.Sprintf("INSERT INTO %s", appsTable)
				mock.ExpectQuery(query).WithArgs(app.Name, app.Secret).WillReturnError(fmt.Errorf("some error"))
			},
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.mockBehavior(test.input)

			actualAppID, err := appsRepository.Add(context.TODO(), test.input)
			if test.isExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedAppID, actualAppID)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestApp_GetByID(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	dbx := sqlx.NewDb(db, "sqlmock")
	appsRepository := NewAppsRepository(dbx)

	type test struct {
		name            string
		mockBehavior    func(appID string)
		input           string
		expected        model.App
		isExpectedError bool
	}

	appID, appName, appSecret := "uuid", "app's name", "app's secret"

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(appID string) {
				rows := sqlmock.NewRows([]string{"id", "name", "secret"}).AddRow(appID, appName, appSecret)
				query := fmt.Sprintf("SELECT (.+) FROM %s", appsTable)
				mock.ExpectQuery(query).WithArgs(appID).WillReturnRows(rows)
			},
			input: appID,
			expected: model.App{
				ID:     appID,
				Name:   appName,
				Secret: appSecret,
			},
			isExpectedError: false,
		},
		{
			name: "App not found error",
			mockBehavior: func(appID string) {
				query := fmt.Sprintf("SELECT (.+) FROM %s", appsTable)
				mock.ExpectQuery(query).WithArgs(appID).WillReturnError(sql.ErrNoRows)
			},
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(appID string) {
				query := fmt.Sprintf("SELECT (.+) FROM %s", appsTable)
				mock.ExpectQuery(query).WithArgs(appID).WillReturnError(fmt.Errorf("some error"))
			},
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.mockBehavior(test.input)

			actual, err := appsRepository.GetByID(context.TODO(), test.input)
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
