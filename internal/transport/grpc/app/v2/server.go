package server

import (
	"context"
	"errors"

	ssov2 "github.com/andredubov/protos/v2/gen/go/sso"
	"github.com/andredubov/sso/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type appsGRPCServer struct {
	ssov2.UnimplementedAppsServer
	appCreator service.AppCreator
}

// NewGRPCAppsServer returns a new instance of application grpc server
func NewGRPCAppsServer(appCreator service.AppCreator) ssov2.AppsServer {
	return &appsGRPCServer{
		appCreator: appCreator,
	}
}

// Create handles grpc request to register a new application in the system and returns result in grpc response
func (a *appsGRPCServer) Create(ctx context.Context, request *ssov2.CreateRequest) (*ssov2.CreateResponse, error) {

	if request.AppName == "" {
		return nil, status.Error(codes.InvalidArgument, "application name is required")
	}

	if request.AppSecret == "" {
		return nil, status.Error(codes.InvalidArgument, "application secret is required")
	}

	id, err := a.appCreator.Create(ctx, request.AppName, request.AppSecret)
	if err != nil {
		if errors.Is(err, service.ErrAppExists) {
			return nil, status.Error(codes.AlreadyExists, "application already exists")
		}
		return nil, status.Error(codes.Internal, "failed to create an application")
	}

	return &ssov2.CreateResponse{AppId: id}, nil
}
