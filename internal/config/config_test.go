package config_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andredubov/sso/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {

	tests := []struct {
		name                string
		enviromentVariables map[string]string
		expectedConfig      *config.Config
		expectedError       error
	}{
		{
			name: "OK",
			enviromentVariables: map[string]string{
				config.ConfigPathEnvVarName:   "../../config/local.yaml",
				config.ApplicationEnvironment: "local",
				config.GrpcHost:               "localhost",
				config.GrpcPort:               "80",
				config.GrpcTimeout:            "7s",
				config.PostgresHost:           "localhost",
				config.PostgresPort:           "1234",
				config.PostgresUsername:       "postgres_23",
				config.PostgresPassword:       "qwerty",
				config.PostgresDatabaseName:   "postgres_456",
				config.PostgresSSLMode:        "disable",
				config.PasswordSalt:           "salt_salt",
				config.JwtSigningKey:          "keysss",
			},
			expectedConfig: &config.Config{
				Enviroment: "local",
				Postgres: config.PostgresConfig{
					Host:         "localhost",
					Port:         1234,
					Username:     "postgres_23",
					Password:     "qwerty",
					DatabaseName: "postgres_456",
					SSLMode:      "disable",
				},
				GRPC: config.GRPCConfig{
					Host:    "localhost",
					Port:    80,
					Timeout: time.Second * 7,
				},
				Auth: config.AuthConfig{
					PasswordSalt: "salt_salt",
					JWT: config.JWTConfig{
						RefreshTokenTTL: time.Minute * 30,
						AccessTokenTTL:  time.Minute * 15,
						SigningKey:      "keysss",
					},
				},
			},
			expectedError: nil,
		},

		{
			name: "config path is empty",
			enviromentVariables: map[string]string{
				config.ConfigPathEnvVarName:   "",
				config.ApplicationEnvironment: "local",
				config.GrpcHost:               "localhost",
				config.GrpcPort:               "80",
				config.GrpcTimeout:            "7s",
				config.PostgresHost:           "localhost",
				config.PostgresPort:           "1234",
				config.PostgresUsername:       "postgres_23",
				config.PostgresPassword:       "qwerty",
				config.PostgresDatabaseName:   "postgres_456",
				config.PostgresSSLMode:        "disable",
				config.PasswordSalt:           "salt_salt",
				config.JwtSigningKey:          "keysss",
			},
			expectedConfig: nil,
			expectedError:  config.ErrEmptyConfigFilePath,
		},

		{
			name: "config file does not exist",
			enviromentVariables: map[string]string{
				config.ConfigPathEnvVarName:   "fake/path/to/config/file.yaml",
				config.ApplicationEnvironment: "local",
				config.GrpcHost:               "localhost",
				config.GrpcPort:               "80",
				config.GrpcTimeout:            "7s",
				config.PostgresHost:           "localhost",
				config.PostgresPort:           "1234",
				config.PostgresUsername:       "postgres",
				config.PostgresPassword:       "qwerty",
				config.PostgresDatabaseName:   "postgres",
				config.PostgresSSLMode:        "disable",
				config.PasswordSalt:           "salt",
				config.JwtSigningKey:          "keysss",
			},
			expectedConfig: nil,
			expectedError:  config.ErrConfigFileDoesNotExist,
		},

		{
			name: "failed to read config",
			enviromentVariables: map[string]string{
				config.ConfigPathEnvVarName: "../../tests/config/test.yaml",
			},
			expectedConfig: nil,
			expectedError:  config.ErrFailedToReadConfigFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			prevEnv := os.Environ()
			for _, entry := range prevEnv {
				parts := strings.SplitN(entry, "=", 2)
				os.Unsetenv(parts[0])
			}
			for key, value := range tt.enviromentVariables {
				os.Setenv(key, value)
			}

			actualConfig, err := config.Load()

			assert.Equal(t, err, tt.expectedError)
			assert.Equal(t, actualConfig, tt.expectedConfig)

			t.Cleanup(func() {
				for key := range tt.enviromentVariables {
					os.Unsetenv(key)
				}
				for _, entry := range prevEnv {
					parts := strings.SplitN(entry, "=", 2)
					os.Setenv(parts[0], parts[1])
				}
			})
		})
	}
}
