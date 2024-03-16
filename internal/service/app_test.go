package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
	mock_repository "github.com/andredubov/sso/internal/repository/mocks"
	"github.com/andredubov/sso/internal/service"
	"github.com/dvln/testify/assert"
	"github.com/golang/mock/gomock"
)

func TestApp_Create(t *testing.T) {

	type test struct {
		name            string
		mockBehavior    func(*mock_repository.MockApps, model.App, string, error)
		input           model.App
		expected        string
		expectedError   error
		isExpectedError bool
	}

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(repo *mock_repository.MockApps, app model.App, id string, err error) {
				repo.EXPECT().Add(gomock.Any(), gomock.Eq(app)).Return(id, err).Times(1)
			},
			input: model.App{
				Name:   "app-name",
				Secret: "app-secret",
			},
			expected:        "uuid",
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "Application already exists",
			mockBehavior: func(repo *mock_repository.MockApps, app model.App, id string, err error) {
				repo.EXPECT().Add(gomock.Any(), gomock.Eq(app)).Return(id, err).Times(1)
			},
			input: model.App{
				Name:   "app-name",
				Secret: "app-secret",
			},
			expected:        "",
			expectedError:   repository.ErrAppExists,
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(repo *mock_repository.MockApps, app model.App, id string, err error) {
				repo.EXPECT().Add(gomock.Any(), gomock.Eq(app)).Return(id, err).Times(1)
			},
			input: model.App{
				Name:   "app-name",
				Secret: "app-secret",
			},
			expected:        "",
			expectedError:   errors.New("some error"),
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAppRepository := mock_repository.NewMockApps(ctrl)
			appCreator := service.NewAppCreator(mockAppRepository)

			test.mockBehavior(mockAppRepository, test.input, test.expected, test.expectedError)

			actual, err := appCreator.Create(context.TODO(), test.input.Name, test.input.Secret)
			if test.isExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, actual)
			}
		})
	}
}
