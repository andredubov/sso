package server_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	ssov2 "github.com/andredubov/protos/v2/gen/go/sso"
	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/service"
	mock_service "github.com/andredubov/sso/internal/service/mocks"
	server "github.com/andredubov/sso/internal/transport/grpc/auth/v2"
	"github.com/dvln/testify/assert"
	"github.com/golang/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestAuthGRPCServer_SignUp(t *testing.T) {

	type MockBehavior func(
		userCreatorMock *mock_service.MockAuth,
		user model.User,
		response *ssov2.SignUpResponse,
		err error,
	)

	type test struct {
		name            string
		mockBehavior    MockBehavior
		input           model.User
		expected        *ssov2.SignUpResponse
		expectedError   error
		isExpectedError bool
	}

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				user model.User,
				response *ssov2.SignUpResponse,
				err error,
			) {
				authCreatorMock.EXPECT().SignUp(gomock.Any(), gomock.Eq(user)).Return("uuid", err).Times(1)
			},
			input: model.User{
				Email:    "app-name",
				Password: "app-secret",
			},
			expected:        &ssov2.SignUpResponse{UserId: "uuid"},
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "User already exists",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				user model.User,
				response *ssov2.SignUpResponse,
				err error,
			) {
				authCreatorMock.EXPECT().SignUp(gomock.Any(), gomock.Eq(user)).Return("", err).Times(1)
			},
			input: model.User{
				Email:    "app-name",
				Password: "app-secret",
			},
			expected:        nil,
			expectedError:   service.ErrUserExists,
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				user model.User,
				response *ssov2.SignUpResponse,
				err error,
			) {
				authCreatorMock.EXPECT().SignUp(gomock.Any(), gomock.Eq(user)).Return("", err).Times(1)
			},
			input: model.User{
				Email:    "app-name",
				Password: "app-secret",
			},
			expected:        nil,
			expectedError:   status.Error(codes.Internal, "failed to register a user"),
			isExpectedError: true,
		},
		{
			name: "Empty user email",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				user model.User,
				response *ssov2.SignUpResponse,
				err error,
			) {

			},
			input: model.User{
				Email:    "",
				Password: "app-secret",
			},
			expected:        nil,
			expectedError:   status.Error(codes.InvalidArgument, "email is required"),
			isExpectedError: true,
		},
		{
			name: "Empty user password",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				user model.User,
				response *ssov2.SignUpResponse,
				err error,
			) {

			},
			input: model.User{
				Email:    "app-name",
				Password: "",
			},
			expected:        nil,
			expectedError:   status.Error(codes.InvalidArgument, "password is required"),
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			t.Cleanup(func() {
				listener.Close()
			})

			srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
			t.Cleanup(func() {
				srv.Stop()
			})

			ctrl := gomock.NewController(t)
			t.Cleanup(func() {
				defer ctrl.Finish()
			})

			authServiceMock := mock_service.NewMockAuth(ctrl)
			authServer := server.NewGRPCAuthServer(authServiceMock)
			ssov2.RegisterAuthServer(srv, authServer)

			go func() {
				if err := srv.Serve(listener); err != nil {
					log.Fatalf("srv.Serve %v", err)
				}
			}()

			dialer := func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			t.Cleanup(func() {
				cancel()
			})

			opts := []grpc.DialOption{
				grpc.WithContextDialer(dialer),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			}

			conn, err := grpc.DialContext(ctx, "", opts...)
			t.Cleanup(func() {
				conn.Close()
			})
			if err != nil {
				t.Fatalf("grpc.DialContext %v", err)
			}

			test.mockBehavior(authServiceMock, test.input, test.expected, test.expectedError)

			client := ssov2.NewAuthClient(conn)

			actual, err := client.SignUp(
				context.TODO(),
				&ssov2.SignUpRequest{Email: test.input.Email, Password: test.input.Password},
			)

			if test.isExpectedError {
				assert.Error(t, err)
				assert.Equal(t, test.expected, actual)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected.UserId, actual.UserId)
			}
		})
	}
}

func TestAuthGRPCServer_SignIn(t *testing.T) {

	type MockBehavior func(
		userCreatorMock *mock_service.MockAuth,
		credentials model.Credentials,
		response *ssov2.SignInResponse,
		err error,
	)

	type test struct {
		name            string
		mockBehavior    MockBehavior
		input           model.Credentials
		expected        *ssov2.SignInResponse
		expectedError   error
		isExpectedError bool
	}

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				cred model.Credentials,
				response *ssov2.SignInResponse,
				err error,
			) {
				authCreatorMock.EXPECT().SignIn(
					gomock.Any(),
					gomock.Eq(cred.Email),
					gomock.Eq(cred.Password),
					gomock.Eq(cred.AppID),
				).Return("token", err).Times(1)
			},
			input: model.Credentials{
				Email:    "user-name",
				Password: "user-secret",
				AppID:    "app-uuid",
			},
			expected:        &ssov2.SignInResponse{Token: "token"},
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "Invalid credentials",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				cred model.Credentials,
				response *ssov2.SignInResponse,
				err error,
			) {
				authCreatorMock.EXPECT().SignIn(
					gomock.Any(),
					gomock.Eq(cred.Email),
					gomock.Eq(cred.Password),
					gomock.Eq(cred.AppID),
				).Return("", err).Times(1)
			},
			input: model.Credentials{
				Email:    "user-name",
				Password: "user-secret",
				AppID:    "app-uuid",
			},
			expected:        nil,
			expectedError:   service.ErrInvalidCredentials,
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				cred model.Credentials,
				response *ssov2.SignInResponse,
				err error,
			) {
				authCreatorMock.EXPECT().SignIn(
					gomock.Any(),
					gomock.Eq(cred.Email),
					gomock.Eq(cred.Password),
					gomock.Eq(cred.AppID),
				).Return("", err).Times(1)
			},
			input: model.Credentials{
				Email:    "user-name",
				Password: "user-secret",
				AppID:    "app-uuid",
			},
			expected:        nil,
			expectedError:   fmt.Errorf("some error"),
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				cred model.Credentials,
				response *ssov2.SignInResponse,
				err error,
			) {
				authCreatorMock.EXPECT().SignIn(
					gomock.Any(),
					gomock.Eq(cred.Email),
					gomock.Eq(cred.Password),
					gomock.Eq(cred.AppID),
				).Return("", err).Times(1)
			},
			input: model.Credentials{
				Email:    "user-name",
				Password: "user-secret",
				AppID:    "app-uuid",
			},
			expected:        nil,
			expectedError:   status.Error(codes.Internal, "failed to login"),
			isExpectedError: true,
		},
		{
			name: "Empty credential email",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				cred model.Credentials,
				response *ssov2.SignInResponse,
				err error,
			) {

			},
			input: model.Credentials{
				Email:    "",
				Password: "user-secret",
				AppID:    "app-uuid",
			},
			expected:        nil,
			expectedError:   status.Error(codes.InvalidArgument, "email is required"),
			isExpectedError: true,
		},
		{
			name: "Empty credential password",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				cred model.Credentials,
				response *ssov2.SignInResponse,
				err error,
			) {

			},
			input: model.Credentials{
				Email:    "user-name",
				Password: "",
				AppID:    "app-uuid",
			},
			expected:        nil,
			expectedError:   status.Error(codes.InvalidArgument, "password is required"),
			isExpectedError: true,
		},
		{
			name: "Empty credential application id",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				cred model.Credentials,
				response *ssov2.SignInResponse,
				err error,
			) {

			},
			input: model.Credentials{
				Email:    "user-name",
				Password: "user-secret",
				AppID:    "",
			},
			expected:        nil,
			expectedError:   status.Error(codes.InvalidArgument, "app id is required"),
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			t.Cleanup(func() {
				listener.Close()
			})

			srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
			t.Cleanup(func() {
				srv.Stop()
			})

			ctrl := gomock.NewController(t)
			t.Cleanup(func() {
				defer ctrl.Finish()
			})

			authServiceMock := mock_service.NewMockAuth(ctrl)
			authServer := server.NewGRPCAuthServer(authServiceMock)
			ssov2.RegisterAuthServer(srv, authServer)

			go func() {
				if err := srv.Serve(listener); err != nil {
					log.Fatalf("srv.Serve %v", err)
				}
			}()

			dialer := func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			t.Cleanup(func() {
				cancel()
			})

			opts := []grpc.DialOption{
				grpc.WithContextDialer(dialer),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			}

			conn, err := grpc.DialContext(ctx, "", opts...)
			t.Cleanup(func() {
				conn.Close()
			})
			if err != nil {
				t.Fatalf("grpc.DialContext %v", err)
			}

			test.mockBehavior(authServiceMock, test.input, test.expected, test.expectedError)

			client := ssov2.NewAuthClient(conn)

			actual, err := client.SignIn(
				context.TODO(),
				&ssov2.SignInRequest{
					Email:    test.input.Email,
					Password: test.input.Password,
					AppId:    test.input.AppID,
				},
			)

			if test.isExpectedError {
				assert.Error(t, err)
				assert.Equal(t, test.expected, actual)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected.Token, actual.Token)
			}
		})
	}
}

func TestAuthGRPCServer_IsAdmin(t *testing.T) {

	type MockBehavior func(
		userCreatorMock *mock_service.MockAuth,
		userID string,
		response *ssov2.IsAdminResponse,
		err error,
	)

	type test struct {
		name            string
		mockBehavior    MockBehavior
		input           string
		expected        *ssov2.IsAdminResponse
		expectedError   error
		isExpectedError bool
	}

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				userID string,
				response *ssov2.IsAdminResponse,
				err error,
			) {
				authCreatorMock.EXPECT().IsAdmin(
					gomock.Any(),
					gomock.Eq(userID),
				).Return(true, err).Times(1)
			},
			input:           "user-uuid",
			expected:        &ssov2.IsAdminResponse{IsAdmin: true},
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "User not found",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				userID string,
				response *ssov2.IsAdminResponse,
				err error,
			) {
				authCreatorMock.EXPECT().IsAdmin(
					gomock.Any(),
					gomock.Eq(userID),
				).Return(false, err).Times(1)
			},
			input:           "user-uuid",
			expected:        nil,
			expectedError:   service.ErrUserNotFound,
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				userID string,
				response *ssov2.IsAdminResponse,
				err error,
			) {
				authCreatorMock.EXPECT().IsAdmin(
					gomock.Any(),
					gomock.Eq(userID),
				).Return(false, err).Times(1)
			},
			input:           "user-uuid",
			expected:        nil,
			expectedError:   status.Error(codes.Internal, "failed to check admin status"),
			isExpectedError: true,
		},
		{
			name: "User id is empty",
			mockBehavior: func(
				authCreatorMock *mock_service.MockAuth,
				userID string,
				response *ssov2.IsAdminResponse,
				err error,
			) {

			},
			input:           "",
			expected:        nil,
			expectedError:   status.Error(codes.InvalidArgument, "user id is required"),
			isExpectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			t.Cleanup(func() {
				listener.Close()
			})

			srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
			t.Cleanup(func() {
				srv.Stop()
			})

			ctrl := gomock.NewController(t)
			t.Cleanup(func() {
				defer ctrl.Finish()
			})

			authServiceMock := mock_service.NewMockAuth(ctrl)
			authServer := server.NewGRPCAuthServer(authServiceMock)
			ssov2.RegisterAuthServer(srv, authServer)

			go func() {
				if err := srv.Serve(listener); err != nil {
					log.Fatalf("srv.Serve %v", err)
				}
			}()

			dialer := func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			t.Cleanup(func() {
				cancel()
			})

			opts := []grpc.DialOption{
				grpc.WithContextDialer(dialer),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			}

			conn, err := grpc.DialContext(ctx, "", opts...)
			t.Cleanup(func() {
				conn.Close()
			})
			if err != nil {
				t.Fatalf("grpc.DialContext %v", err)
			}

			test.mockBehavior(authServiceMock, test.input, test.expected, test.expectedError)

			client := ssov2.NewAuthClient(conn)

			actual, err := client.IsAdmin(
				context.TODO(),
				&ssov2.IsAdminRequest{UserId: test.input},
			)

			if test.isExpectedError {
				assert.Error(t, err)
				assert.Equal(t, test.expected, actual)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected.IsAdmin, actual.IsAdmin)
			}
		})
	}
}
