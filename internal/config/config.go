package config

import (
	"errors"
	"flag"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

const (
	ConfigPathEnvVarName = "CONFIG_PATH"
	ConfigPathFlagName   = "config"
	EmptyString          = ""

	ApplicationEnvironment = "APP_ENV"
	GrpcHost               = "GRPC_HOST"
	GrpcPort               = "GRPC_PORT"
	GrpcTimeout            = "GRPC_TIMEOUT"
	PostgresHost           = "DB_HOST"
	PostgresPort           = "DB_PORT"
	PostgresDatabaseName   = "DB_NAME"
	PostgresUsername       = "DB_USER"
	PostgresPassword       = "DB_PASSWORD"
	PostgresSSLMode        = "DB_SSL_MODE"
	PasswordSalt           = "PASSWORD_SALT"
	JwtSigningKey          = "JWT_SIGNING_KEY"
)

var (
	ErrEmptyConfigFilePath    = errors.New("config path is empty")
	ErrConfigFileDoesNotExist = errors.New("config file does't exist")
	ErrConfigFileParsing      = errors.New("config file parsing error: EOF")
	ErrFailedToReadConfigFile = errors.New("failed to read config")
)

type (
	Config struct {
		Enviroment string   `yaml:"env" env:"APP_ENV" env-default:"local"`
		Postgres   Postgres `yaml:"postgres"`
		GRPC       GRPC     `yaml:"grpc"`
		Auth       Auth     `yaml:"auth"`
	}

	Postgres struct {
		Host         string `yaml:"host" env:"DB_HOST"`
		Port         int    `yaml:"port" env:"DB_PORT"`
		Username     string `yaml:"username" env:"DB_USER"`
		Password     string `yaml:"password" env:"DB_PASSWORD"`
		DatabaseName string `yaml:"databasename" env:"DB_NAME"`
		SSLMode      string `yaml:"sslmode" env:"DB_SSL_MODE"`
	}

	GRPC struct {
		Host    string        `yaml:"host" env:"GRPC_HOST"`
		Port    int           `yaml:"port" env:"GRPC_PORT"`
		Timeout time.Duration `yaml:"timeout" env:"GRPC_TIMEOUT"`
	}

	Auth struct {
		JWT          JWT    `yaml:"jwt"`
		PasswordSalt string `yaml:"passwordSalt" env:"PASSWORD_SALT"`
	}

	JWT struct {
		AccessTokenTTL  time.Duration `yaml:"accessTokenTTL" env:"JWT_ACCESS_TOKEN_TTL"`
		RefreshTokenTTL time.Duration `yaml:"refreshTokenTTL" env:"JWT_REFRESH_TOKEN_TTL"`
		SigningKey      string        `yaml:"signinKey" env:"JWT_SIGNING_KEY"`
	}
)

// Load populates Config struct with values from config file located at filepath and from enviroment variables
func Load() (*Config, error) {

	configPath := fetchConfigPath()
	if configPath == EmptyString {
		return nil, ErrEmptyConfigFilePath
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, ErrConfigFileDoesNotExist
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		return nil, ErrFailedToReadConfigFile
	}

	return &cfg, nil
}

// fetchConfigPath fetches config path from command line flag or enviroment variable
// priority: flag > env > default
// default value is empty string
func fetchConfigPath() string {

	var result string

	// --config="path/to/config.yaml"
	if flag.Lookup(ConfigPathFlagName) == nil {
		flag.StringVar(&result, ConfigPathFlagName, EmptyString, "path to config file")
	}
	flag.Parse()

	if result == EmptyString {
		result = os.Getenv(ConfigPathEnvVarName)
	}

	return result
}
