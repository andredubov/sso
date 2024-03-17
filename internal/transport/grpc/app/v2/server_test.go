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
	server "github.com/andredubov/sso/internal/transport/grpc/app/v2"
	"github.com/dvln/testify/assert"
	"github.com/golang/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestAppGRPCServer_Create(t *testing.T) {

	type MockBehavior func(
		appCreatorMock *mock_service.MockAppCreator,
		app model.App,
		response *ssov2.CreateResponse,
		err error,
	)

	type test struct {
		name            string
		mockBehavior    MockBehavior
		input           model.App
		expected        *ssov2.CreateResponse
		expectedError   error
		isExpectedError bool
	}

	tests := []test{
		{
			name: "Success",
			mockBehavior: func(
				appCreatorMock *mock_service.MockAppCreator,
				app model.App,
				response *ssov2.CreateResponse,
				err error,
			) {
				appCreatorMock.EXPECT().Create(gomock.Any(), app.Name, app.Secret).Return("uuid", err).Times(1)
			},
			input: model.App{
				Name:   "app-name",
				Secret: "app-secret",
			},
			expected:        &ssov2.CreateResponse{AppId: "uuid"},
			expectedError:   nil,
			isExpectedError: false,
		},
		{
			name: "App already exists",
			mockBehavior: func(
				appCreatorMock *mock_service.MockAppCreator,
				app model.App,
				response *ssov2.CreateResponse,
				err error,
			) {
				appCreatorMock.EXPECT().Create(gomock.Any(), app.Name, app.Secret).Return("", err).Times(1)
			},
			input: model.App{
				Name:   "app-name",
				Secret: "app-secret",
			},
			expected:        nil,
			expectedError:   service.ErrAppExists,
			isExpectedError: true,
		},
		{
			name: "Unknown error",
			mockBehavior: func(
				appCreatorMock *mock_service.MockAppCreator,
				app model.App,
				response *ssov2.CreateResponse,
				err error,
			) {
				appCreatorMock.EXPECT().Create(gomock.Any(), gomock.Eq(app.Name), gomock.Eq(app.Secret)).Return("", err).Times(1)
			},
			input: model.App{
				Name:   "app-name",
				Secret: "app-secret",
			},
			expected:        nil,
			expectedError:   status.Error(codes.Internal, "failed to create an application"),
			isExpectedError: true,
		},
		{
			name: "Empty application name",
			mockBehavior: func(
				appCreatorMock *mock_service.MockAppCreator,
				app model.App,
				response *ssov2.CreateResponse,
				err error,
			) {

			},
			input: model.App{
				Name:   "",
				Secret: "app-secret",
			},
			expected:        nil,
			expectedError:   status.Error(codes.InvalidArgument, "application name is required"),
			isExpectedError: true,
		},
		{
			name: "Empty application secret",
			mockBehavior: func(
				appCreatorMock *mock_service.MockAppCreator,
				app model.App,
				response *ssov2.CreateResponse,
				err error,
			) {

			},
			input: model.App{
				Name:   "app-name",
				Secret: "",
			},
			expected:        nil,
			expectedError:   status.Error(codes.InvalidArgument, "application secret is required"),
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

			appCreatorMock := mock_service.NewMockAppCreator(ctrl)
			appsServer := server.NewGRPCAppsServer(appCreatorMock)
			ssov2.RegisterAppsServer(srv, appsServer)

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

			test.mockBehavior(appCreatorMock, test.input, test.expected, test.expectedError)

			client := ssov2.NewAppsClient(conn)

			actual, err := client.Create(
				context.TODO(),
				&ssov2.CreateRequest{AppName: test.input.Name, AppSecret: test.input.Secret},
			)

			if test.isExpectedError {
				assert.Error(t, err)
				assert.Equal(t, test.expected, actual)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected.AppId, actual.AppId)
			}
		})
	}
}
