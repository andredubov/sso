package service_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/andredubov/sso/internal/config"
	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
	mock_repository "github.com/andredubov/sso/internal/repository/mocks"
	"github.com/andredubov/sso/internal/service"
	mock_auth "github.com/andredubov/sso/pkg/auth/mocks"
	mock_hash "github.com/andredubov/sso/pkg/hash/mocks"
	"github.com/dvln/testify/assert"
	"github.com/golang/mock/gomock"
)

func TestAuth_SignUp(t *testing.T) {

	type mockBehavior func(
		usersRepositoryMock *mock_repository.MockUsers,
		passwordHasherMock *mock_hash.MockPasswordHasher,
		user model.User,
		userPasswordHash string,
		userID string,
		err error,
	)

	type test struct {
		name            string
		mockBehavior    mockBehavior
		input           model.User
		passwordHash    string
		expected        string
		expectedError   error
		isExpectedError bool
	}

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				user model.User,
				userPasswordHash string,
				id string,
				err error,
			) {
				firstCall := passwordHasherMock.EXPECT().HashAndSalt(gomock.Eq(user.Password))
				firstCall.Return(userPasswordHash, nil).Times(1)

				u := model.User{Email: user.Email, Password: userPasswordHash}

				secondCall := usersRepositoryMock.EXPECT().Add(gomock.Any(), gomock.Eq(u))
				secondCall.Return(id, err).Times(1).After(firstCall)
			},
			input: model.User{
				Email:    "user-email",
				Password: "user-password",
			},
			passwordHash:    "user-password-hash",
			expected:        "uuid",
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "User already exists",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				user model.User,
				userPasswordHash string,
				id string,
				err error,
			) {
				firstCall := passwordHasherMock.EXPECT().HashAndSalt(gomock.Eq(user.Password))
				firstCall.Return(userPasswordHash, nil).Times(1)

				u := model.User{Email: user.Email, Password: userPasswordHash}

				secondCall := usersRepositoryMock.EXPECT().Add(gomock.Any(), gomock.Eq(u))
				secondCall.Return(id, err).Times(1).After(firstCall)
			},
			input: model.User{
				Email:    "user-email",
				Password: "user-password",
			},
			passwordHash:    "user-password-hash",
			expected:        "",
			expectedError:   repository.ErrUserExists,
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				user model.User,
				userPasswordHash string,
				id string,
				err error,
			) {
				firstCall := passwordHasherMock.EXPECT().HashAndSalt(gomock.Eq(user.Password))
				firstCall.Return(userPasswordHash, nil).Times(1)

				u := model.User{Email: user.Email, Password: userPasswordHash}

				secondCall := usersRepositoryMock.EXPECT().Add(gomock.Any(), gomock.Eq(u))
				secondCall.Return(id, err).Times(1).After(firstCall)
			},
			input: model.User{
				Email:    "user-email",
				Password: "user-password",
			},
			passwordHash:    "user-password-hash",
			expected:        "",
			expectedError:   errors.New("some error"),
			isExpectedError: true,
		},
		{
			name: "Password hasher error",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				user model.User,
				userPasswordHash string,
				id string,
				err error,
			) {
				firstCall := passwordHasherMock.EXPECT().HashAndSalt(gomock.Eq(user.Password))
				firstCall.Return(userPasswordHash, err).Times(1)
			},
			input: model.User{
				Email:    "user-email",
				Password: "user-password",
			},
			passwordHash:    "",
			expected:        "",
			expectedError:   errors.New("hasher error"),
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			usersRepoMock := mock_repository.NewMockUsers(ctrl)
			appsRepoMock := mock_repository.NewMockApps(ctrl)
			mockManager := mock_auth.NewMockTokenManager(ctrl)
			passwordHasherMock := mock_hash.NewMockPasswordHasher(ctrl)
			cfg := config.JWT{AccessTokenTTL: 5 * time.Minute}

			repo := &repository.Repository{
				Users: usersRepoMock,
				Apps:  appsRepoMock,
			}

			authService := service.NewAuthService(
				repo,
				passwordHasherMock,
				mockManager,
				cfg,
			)

			test.mockBehavior(
				usersRepoMock,
				passwordHasherMock,
				test.input,
				test.passwordHash,
				test.expected,
				test.expectedError,
			)

			actual, err := authService.SignUp(context.TODO(), test.input)

			if test.isExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestAuth_SignIn(t *testing.T) {

	type inputData struct {
		UserEmail    string
		UserPassword string
		AppID        string
	}

	type mockBehavior func(
		usersRepositoryMock *mock_repository.MockUsers,
		appsRepositoryMock *mock_repository.MockApps,
		passwordHasherMock *mock_hash.MockPasswordHasher,
		tokenManagerMock *mock_auth.MockTokenManager,
		input inputData,
		userPasswordHash string,
		userID string,
		cfg config.JWT,
		token string,
		err error,
	)

	type test struct {
		name            string
		mockBehavior    mockBehavior
		input           inputData
		passwordHash    string
		userID          string
		cfg             config.JWT
		expected        string
		expectedError   error
		isExpectedError bool
	}

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				appsRepositoryMock *mock_repository.MockApps,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				tokenManagerMock *mock_auth.MockTokenManager,
				input inputData,
				userPasswordHash string,
				userID string,
				cfg config.JWT,
				token string,
				err error,
			) {
				user := model.User{ID: userID, Email: input.UserEmail, Password: userPasswordHash}
				firstCall := usersRepositoryMock.EXPECT().GetByEmail(
					gomock.Any(),
					gomock.Eq(input.UserEmail),
				)
				firstCall.Return(user, nil).Times(1)

				secondCall := passwordHasherMock.EXPECT().ComparePasswords(
					gomock.Eq(user.Password),
					gomock.Eq(input.UserPassword),
				)
				secondCall.Return(nil).Times(1).After(firstCall)

				app := model.App{ID: input.AppID}
				thirdCall := appsRepositoryMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(input.AppID))
				thirdCall.Return(app, nil).Times(1).After(secondCall)

				fourthCall := tokenManagerMock.EXPECT().NewJWT(
					gomock.Eq(user),
					gomock.Eq(app),
					gomock.Eq(cfg.AccessTokenTTL),
				)
				fourthCall.Return(token, err).Times(1).After(thirdCall)
			},
			input: inputData{
				UserEmail:    "user-email",
				UserPassword: "user-password",
				AppID:        "appID",
			},
			passwordHash:    "user-password-hash",
			userID:          "userID",
			cfg:             config.JWT{AccessTokenTTL: 5 * time.Minute},
			expected:        "token",
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "User not found by email (wrong user email)",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				appsRepositoryMock *mock_repository.MockApps,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				tokenManagerMock *mock_auth.MockTokenManager,
				input inputData,
				userPasswordHash string,
				userID string,
				cfg config.JWT,
				token string,
				err error,
			) {
				firstCall := usersRepositoryMock.EXPECT().GetByEmail(
					gomock.Any(),
					gomock.Eq(input.UserEmail),
				)
				firstCall.Return(model.User{}, err).Times(1)
			},
			input: inputData{
				UserEmail:    "user-email",
				UserPassword: "user-password",
				AppID:        "appID",
			},
			passwordHash:    "user-password-hash",
			userID:          "userID",
			cfg:             config.JWT{AccessTokenTTL: 5 * time.Minute},
			expected:        "",
			expectedError:   repository.ErrUserNotFound,
			isExpectedError: true,
		},
		{
			name: "User not found by email (unknown error)",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				appsRepositoryMock *mock_repository.MockApps,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				tokenManagerMock *mock_auth.MockTokenManager,
				input inputData,
				userPasswordHash string,
				userID string,
				cfg config.JWT,
				token string,
				err error,
			) {
				firstCall := usersRepositoryMock.EXPECT().GetByEmail(
					gomock.Any(),
					gomock.Eq(input.UserEmail),
				)
				firstCall.Return(model.User{}, err).Times(1)
			},
			input: inputData{
				UserEmail:    "user-email",
				UserPassword: "user-password",
				AppID:        "appID",
			},
			passwordHash:    "user-password-hash",
			userID:          "userID",
			cfg:             config.JWT{AccessTokenTTL: 5 * time.Minute},
			expected:        "",
			expectedError:   errors.New("some error"),
			isExpectedError: true,
		},
		{
			name: "Invalid credentials (wrong user password)",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				appsRepositoryMock *mock_repository.MockApps,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				tokenManagerMock *mock_auth.MockTokenManager,
				input inputData,
				userPasswordHash string,
				userID string,
				cfg config.JWT,
				token string,
				err error,
			) {
				user := model.User{ID: userID, Email: input.UserEmail, Password: userPasswordHash}
				firstCall := usersRepositoryMock.EXPECT().GetByEmail(
					gomock.Any(),
					gomock.Eq(input.UserEmail),
				)
				firstCall.Return(user, nil).Times(1)

				secondCall := passwordHasherMock.EXPECT().ComparePasswords(
					gomock.Eq(user.Password),
					gomock.Eq(input.UserPassword),
				)
				secondCall.Return(err).Times(1).After(firstCall)
			},
			input: inputData{
				UserEmail:    "user-email",
				UserPassword: "user-password",
				AppID:        "appID",
			},
			passwordHash:    "user-password-hash",
			userID:          "userID",
			cfg:             config.JWT{AccessTokenTTL: 5 * time.Minute},
			expected:        "",
			expectedError:   fmt.Errorf("some error"),
			isExpectedError: true,
		},
		{
			name: "App not found (wrong app ID)",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				appsRepositoryMock *mock_repository.MockApps,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				tokenManagerMock *mock_auth.MockTokenManager,
				input inputData,
				userPasswordHash string,
				userID string,
				cfg config.JWT,
				token string,
				err error,
			) {
				user := model.User{ID: userID, Email: input.UserEmail, Password: userPasswordHash}
				firstCall := usersRepositoryMock.EXPECT().GetByEmail(
					gomock.Any(),
					gomock.Eq(input.UserEmail),
				)
				firstCall.Return(user, nil).Times(1)

				secondCall := passwordHasherMock.EXPECT().ComparePasswords(
					gomock.Eq(user.Password),
					gomock.Eq(input.UserPassword),
				)
				secondCall.Return(nil).Times(1).After(firstCall)

				thirdCall := appsRepositoryMock.EXPECT().GetByID(
					gomock.Any(),
					gomock.Eq(input.AppID),
				)
				thirdCall.Return(model.App{}, err).Times(1).After(secondCall)
			},
			input: inputData{
				UserEmail:    "user-email",
				UserPassword: "user-password",
				AppID:        "appID",
			},
			passwordHash:    "user-password-hash",
			userID:          "userID",
			cfg:             config.JWT{AccessTokenTTL: 5 * time.Minute},
			expected:        "",
			expectedError:   repository.ErrAppNotFound,
			isExpectedError: true,
		},
		{
			name: "App not found (unknown error)",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				appsRepositoryMock *mock_repository.MockApps,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				tokenManagerMock *mock_auth.MockTokenManager,
				input inputData,
				userPasswordHash string,
				userID string,
				cfg config.JWT,
				token string,
				err error,
			) {
				user := model.User{ID: userID, Email: input.UserEmail, Password: userPasswordHash}
				firstCall := usersRepositoryMock.EXPECT().GetByEmail(
					gomock.Any(),
					gomock.Eq(input.UserEmail),
				)
				firstCall.Return(user, nil).Times(1)

				secondCall := passwordHasherMock.EXPECT().ComparePasswords(
					gomock.Eq(user.Password),
					gomock.Eq(input.UserPassword),
				)
				secondCall.Return(nil).Times(1).After(firstCall)

				thirdCall := appsRepositoryMock.EXPECT().GetByID(
					gomock.Any(),
					gomock.Eq(input.AppID),
				)
				thirdCall.Return(model.App{}, err).Times(1).After(secondCall)
			},
			input: inputData{
				UserEmail:    "user-email",
				UserPassword: "user-password",
				AppID:        "appID",
			},
			passwordHash:    "user-password-hash",
			userID:          "userID",
			cfg:             config.JWT{AccessTokenTTL: 5 * time.Minute},
			expected:        "",
			expectedError:   errors.New("some error"),
			isExpectedError: true,
		},
		{
			name: "JWT token manger unknown error",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				appsRepositoryMock *mock_repository.MockApps,
				passwordHasherMock *mock_hash.MockPasswordHasher,
				tokenManagerMock *mock_auth.MockTokenManager,
				input inputData,
				userPasswordHash string,
				userID string,
				cfg config.JWT,
				token string,
				err error,
			) {
				user := model.User{ID: userID, Email: input.UserEmail, Password: userPasswordHash}
				firstCall := usersRepositoryMock.EXPECT().GetByEmail(
					gomock.Any(),
					gomock.Eq(input.UserEmail),
				)
				firstCall.Return(user, nil).Times(1)

				secondCall := passwordHasherMock.EXPECT().ComparePasswords(
					gomock.Eq(user.Password),
					gomock.Eq(input.UserPassword),
				)
				secondCall.Return(nil).Times(1).After(firstCall)

				thirdCall := appsRepositoryMock.EXPECT().GetByID(
					gomock.Any(),
					gomock.Eq(input.AppID),
				)
				thirdCall.Return(model.App{ID: input.AppID}, nil).Times(1).After(secondCall)

				fourthCall := tokenManagerMock.EXPECT().NewJWT(
					gomock.Eq(user),
					gomock.Eq(model.App{ID: input.AppID}),
					gomock.Eq(cfg.AccessTokenTTL),
				)
				fourthCall.Return(token, err).Times(1).After(thirdCall)
			},
			input: inputData{
				UserEmail:    "user-email",
				UserPassword: "user-password",
				AppID:        "appID",
			},
			passwordHash:    "user-password-hash",
			userID:          "userID",
			cfg:             config.JWT{AccessTokenTTL: 5 * time.Minute},
			expected:        "",
			expectedError:   fmt.Errorf("some error"),
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			usersRepositoryMock := mock_repository.NewMockUsers(ctrl)
			appsRepositoryMock := mock_repository.NewMockApps(ctrl)
			tokenManagerMock := mock_auth.NewMockTokenManager(ctrl)
			passwordHasherMock := mock_hash.NewMockPasswordHasher(ctrl)
			cfg := config.JWT{AccessTokenTTL: 5 * time.Minute}

			repo := &repository.Repository{
				Users: usersRepositoryMock,
				Apps:  appsRepositoryMock,
			}

			authService := service.NewAuthService(
				repo,
				passwordHasherMock,
				tokenManagerMock,
				cfg,
			)

			test.mockBehavior(
				usersRepositoryMock,
				appsRepositoryMock,
				passwordHasherMock,
				tokenManagerMock,
				test.input,
				test.passwordHash,
				test.userID,
				test.cfg,
				test.expected,
				test.expectedError,
			)

			actual, err := authService.SignIn(
				context.TODO(),
				test.input.UserEmail,
				test.input.UserPassword,
				test.input.AppID,
			)

			if test.isExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestAuth_IsAdmin(t *testing.T) {

	type mockBehavior func(
		usersRepositoryMock *mock_repository.MockUsers,
		user model.User,
		isAdmin bool,
		err error,
	)

	type test struct {
		name            string
		mockBehavior    mockBehavior
		input           model.User
		expected        bool
		expectedError   error
		isExpectedError bool
	}

	tests := []test{
		{
			name: "Success (user is admin)",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				user model.User,
				isAdmin bool,
				err error,
			) {
				firstCall := usersRepositoryMock.EXPECT().IsAdmin(gomock.Any(), gomock.Eq(user.ID))
				firstCall.Return(isAdmin, err).Times(1)
			},
			input: model.User{
				ID: "uuid",
			},
			expected:        true,
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "Success (user isn't admin)",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				user model.User,
				isAdmin bool,
				err error,
			) {
				firstCall := usersRepositoryMock.EXPECT().IsAdmin(gomock.Any(), gomock.Eq(user.ID))
				firstCall.Return(isAdmin, err).Times(1)
			},
			input: model.User{
				ID: "uuid",
			},
			expected:        false,
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "User not found",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				user model.User,
				isAdmin bool,
				err error,
			) {
				firstCall := usersRepositoryMock.EXPECT().IsAdmin(gomock.Any(), gomock.Eq(user.ID))
				firstCall.Return(isAdmin, err).Times(1)
			},
			input: model.User{
				ID: "uuid",
			},
			expected:        false,
			expectedError:   service.ErrUserNotFound,
			isExpectedError: true,
		},
		{
			name: "User not found",
			mockBehavior: func(
				usersRepositoryMock *mock_repository.MockUsers,
				user model.User,
				isAdmin bool,
				err error,
			) {
				firstCall := usersRepositoryMock.EXPECT().IsAdmin(gomock.Any(), gomock.Eq(user.ID))
				firstCall.Return(isAdmin, err).Times(1)
			},
			input: model.User{
				ID: "uuid",
			},
			expected:        false,
			expectedError:   repository.ErrUserNotFound,
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			usersRepositoryMock := mock_repository.NewMockUsers(ctrl)
			appsRepositoryMock := mock_repository.NewMockApps(ctrl)
			mockManager := mock_auth.NewMockTokenManager(ctrl)
			passwordHasherMock := mock_hash.NewMockPasswordHasher(ctrl)
			cfg := config.JWT{AccessTokenTTL: 5 * time.Minute}

			repo := &repository.Repository{
				Users: usersRepositoryMock,
				Apps:  appsRepositoryMock,
			}

			authService := service.NewAuthService(
				repo,
				passwordHasherMock,
				mockManager,
				cfg,
			)

			test.mockBehavior(
				usersRepositoryMock,
				test.input,
				test.expected,
				test.expectedError,
			)

			actual, err := authService.IsAdmin(context.TODO(), test.input.ID)

			if test.isExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.expected, actual)
		})
	}
}
