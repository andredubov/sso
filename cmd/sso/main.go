package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/andredubov/sso/internal/app"
	"github.com/andredubov/sso/pkg/logger"
)

func main() {

	const op = "main"

	application, err := app.New()
	if err != nil {
		logger.Errorf("%s: %s", op, err)
		return
	}

	go func() {
		if err := application.Run(); err != nil {
			logger.Errorf("%s: %s", op, err)
		}
	}()

	logger.Info("Auth gRPC server started.")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	<-quit

	application.Stop()

	logger.Info("Auth gRPC server gracefully stopped.")
}
