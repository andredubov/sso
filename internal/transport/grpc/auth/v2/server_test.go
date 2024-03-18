package server_test

import (
	"context"
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
		app model.User,
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
