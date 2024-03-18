package server

import (
	"context"
	"errors"

	ssov2 "github.com/andredubov/protos/v2/gen/go/sso"
	"github.com/andredubov/sso/internal/domain/model"
	"github.com/andredubov/sso/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authGRPCServer struct {
	ssov2.UnimplementedAuthServer
	auth service.Auth
}

// NewGRPCAuthServer returns an instance of Auth grpc server
func NewGRPCAuthServer(service service.Auth) ssov2.AuthServer {
	return &authGRPCServer{
		auth: service,
	}
}

// SignUp handles grpc request to register a user in the system and returns result in grpc response
func (a *authGRPCServer) SignUp(ctx context.Context, request *ssov2.SignUpRequest) (*ssov2.SignUpResponse, error) {

	if request.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if request.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	id, err := a.auth.SignUp(ctx, model.User{Email: request.Email, Password: request.Password})
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register a user")
	}

	return &ssov2.SignUpResponse{UserId: id}, nil
}

// SignIn handles grpc request to sign a user in the system and returns result in grpc response
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

	token, err := a.auth.SignIn(ctx, request.Email, request.Password, request.AppId)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &ssov2.SignInResponse{Token: token}, nil
}

// SignOut handles grpc request to logout user from the system and returns result in grpc response
func (a *authGRPCServer) SignOut(ctx context.Context, request *ssov2.SignOutRequest) (*ssov2.SignOutResponse, error) {

	return nil, status.Errorf(codes.Unimplemented, "method SignOut not implemented")
}

// IsAdmin handles grpc request to check if a user is admin and then send checks result by grpc reponse
func (a *authGRPCServer) IsAdmin(ctx context.Context, request *ssov2.IsAdminRequest) (*ssov2.IsAdminResponse, error) {

	if request.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user id is required")
	}

	isAdmin, err := a.auth.IsAdmin(ctx, request.UserId)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to check admin status")
	}

	return &ssov2.IsAdminResponse{IsAdmin: isAdmin}, nil
}
