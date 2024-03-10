package server

import (
	"context"
	"errors"

	ssov2 "github.com/andredubov/protos/v2/gen/go/sso"
	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/repository"
	"github.com/andredubov/sso/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authGRPCServer struct {
	ssov2.UnimplementedAuthServer
	service *service.Service
}

func NewGRPCAuthServer(service *service.Service) ssov2.AuthServer {
	return &authGRPCServer{
		service: service,
	}
}

func (a *authGRPCServer) SignUp(ctx context.Context, request *ssov2.SignUpRequest) (*ssov2.SignUpResponse, error) {

	if request.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if request.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	id, err := a.service.Auth.SignUp(ctx, model.User{Email: request.Email, Password: request.Password})
	if err != nil {
		if errors.Is(err, repository.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register a user")
	}

	return &ssov2.SignUpResponse{UserId: id}, nil
}

func (a *authGRPCServer) SignIn(ctx context.Context, request *ssov2.SignInRequest) (*ssov2.SignInResponse, error) {
	if request.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if request.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if request.GetAppId() == "" {
		return nil, status.Error(codes.InvalidArgument, "app id is required")
	}

	token, err := a.service.Auth.SignIn(ctx, request.Email, request.Password, request.AppId)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &ssov2.SignInResponse{Token: token}, nil
}

func (a *authGRPCServer) SignOut(ctx context.Context, request *ssov2.SignOutRequest) (*ssov2.SignOutResponse, error) {

	return nil, status.Errorf(codes.Unimplemented, "method SignOut not implemented")
}

func (a *authGRPCServer) IsAdmin(ctx context.Context, request *ssov2.IsAdminRequest) (*ssov2.IsAdminResponse, error) {

	if request.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user id is required")
	}

	isAdmin, err := a.service.Auth.IsAdmin(ctx, request.UserId)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to check admin status")
	}

	return &ssov2.IsAdminResponse{IsAdmin: isAdmin}, nil
}
