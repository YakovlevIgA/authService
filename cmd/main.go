package main

import (
	"context"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"seventhOne-auth/internal/config"
	customLogger "seventhOne-auth/internal/logger"
	"seventhOne-auth/internal/repo"
	"seventhOne-auth/internal/service"
	"seventhOne-auth/pkg/jwt"
	fromproto "seventhOne-auth/protos/gen/proto"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	if err := godotenv.Load(".env"); err != nil {
		log.Fatal(errors.Wrap(err, "failed to load environment variables"))
	}

	var cfg config.AppConfig
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatal(errors.Wrap(err, "failed to load configuration"))
	}

	logger, err := customLogger.NewLogger(cfg.LogLevel)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error initializing logger"))
	}

	privateKey, err := jwt.ReadPrivateKey()
	if err != nil {
		log.Fatal("failed to read private key")
	}
	publicKey, err := jwt.ReadPublicKey()
	if err != nil {
		log.Fatal("failed to read public key")
	}

	jwt := jwt.NewJWTClient(privateKey, publicKey, cfg.System.AccessTokenTimeout, cfg.System.RefreshTokenTimeout)

	repository, err := repo.NewRepository(context.Background(), cfg.PostgreSQL, logger)
	if err != nil {
		log.Fatal(errors.Wrap(err, "failed to initialize repository"))
	}

	serviceInstance := service.NewService(cfg, repository, logger, jwt)

	server := grpc.NewServer()
	fromproto.RegisterAuthServiceServer(server, serviceInstance)

	lis, err := net.Listen("tcp", ":"+cfg.GRPC.ListenAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	go func() {
		logger.Infof("starting gRPC server on %s", cfg.GRPC.ListenAddress)
		if err := server.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	<-signalChan

	logger.Info("Shutting down gracefully...")
	if err := repo.RollbackMigrations(repository, logger); err != nil {
		logger.Errorf("Failed to rollback migrations: %v", err)
	} else {
		logger.Info("Migrations successfully rolled back")
	}
	server.GracefulStop()
}
