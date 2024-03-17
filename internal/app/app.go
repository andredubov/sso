package app

import (
	"fmt"
	"net"
	"strconv"

	ssov2 "github.com/andredubov/protos/v2/gen/go/sso"
	"github.com/andredubov/sso/internal/config"
	"github.com/andredubov/sso/internal/repository/postgres"
	"github.com/andredubov/sso/internal/service"
	appsServer "github.com/andredubov/sso/internal/transport/grpc/app/v2"
	authserver "github.com/andredubov/sso/internal/transport/grpc/auth/v2"
	"github.com/andredubov/sso/pkg/auth"
	"github.com/andredubov/sso/pkg/database"
	"github.com/andredubov/sso/pkg/hash"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

type Application interface {
	Run() error
	Stop()
}

type app struct {
	grpcServer *grpc.Server
	cfg        *config.Config
	auth       service.Auth
	appCreator service.AppCreator
}

func New() (Application, error) {

	const op = "app.New"

	a := new(app)

	if err := a.initDeps(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return a, nil
}

func (a *app) Run() error {

	const op = "server.Run"

	address := net.JoinHostPort("", strconv.Itoa(a.cfg.GRPC.Port))
	listen, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := a.grpcServer.Serve(listen); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *app) Stop() {
	a.grpcServer.GracefulStop()
}

func (a *app) initDeps() error {

	const op = "app.initDeps"

	initSteps := []func() error{
		a.initConfig,
		a.initServices,
		a.initGRPCServer,
	}

	for _, initStep := range initSteps {
		if err := initStep(); err != nil {
			return fmt.Errorf("%s, %w", op, err)
		}
	}

	return nil
}

func (a *app) initConfig() error {

	const op = "app.initConfig"

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	a.cfg = cfg

	return nil
}

func (a *app) initServices() error {

	const op = "app.initServices"

	db, err := database.NewPostgresConnection(&a.cfg.Postgres)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	repo, hasher := postgres.NewRepository(db), hash.NewCryptoHasher(bcrypt.DefaultCost)

	tokenManager, err := auth.NewTokenManager(a.cfg.Auth.JWT.SigningKey)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	a.auth = service.NewAuthService(repo, hasher, tokenManager, a.cfg.Auth.JWT)
	a.appCreator = service.NewAppCreator(repo.Apps)

	return nil
}

func (a *app) initGRPCServer() error {

	opts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
		grpc.ConnectionTimeout(a.cfg.GRPC.Timeout),
	}

	a.grpcServer = grpc.NewServer(opts...)

	reflection.Register(a.grpcServer)

	authServer := authserver.NewGRPCAuthServer(a.auth)
	appsServer := appsServer.NewGRPCAppsServer(a.appCreator)

	ssov2.RegisterAuthServer(a.grpcServer, authServer)
	ssov2.RegisterAppsServer(a.grpcServer, appsServer)

	return nil
}
