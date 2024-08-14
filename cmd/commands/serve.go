package commands

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bogatyr285/auth-go/config"
	"github.com/bogatyr285/auth-go/internal/auth/repository"
	"github.com/bogatyr285/auth-go/internal/auth/usecase"
	"github.com/bogatyr285/auth-go/internal/buildinfo"
	"github.com/bogatyr285/auth-go/internal/gateway/grpc/auth"
	"github.com/bogatyr285/auth-go/internal/gateway/http/gen"
	"github.com/bogatyr285/auth-go/pkg/crypto"
	"github.com/bogatyr285/auth-go/pkg/jwt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"
)

func NewServeCmd() *cobra.Command {
	var configPath string

	c := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"s"},
		Short:   "Start API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
			defer cancel()

			cfg, err := config.Parse(configPath)
			if err != nil {
				return err
			}

			storage, err := repository.New(cfg.Storage.SQLitePath)
			if err != nil {
				return err
			}

			passwordHasher := crypto.NewPasswordHasher()
			jwtManager, err := jwt.NewJWTManager(
				cfg.JWT.Issuer,
				cfg.JWT.ExpiresIn,
				[]byte(cfg.JWT.PublicKey),
				[]byte(cfg.JWT.PrivateKey))
			if err != nil {
				return err
			}

			useCase := usecase.NewUseCase(&storage,
				passwordHasher,
				jwtManager,
				buildinfo.New(),
			)

			router := chi.NewRouter()
			router.Use(middleware.Logger)
			router.Use(middleware.RequestID)
			router.Use(middleware.Recoverer)
			router.Route("/users", func(r chi.Router) {
				router.Use(useCase.AuthMiddleware)
			})

			httpServer := http.Server{
				Addr:         cfg.HTTPServer.Address,
				ReadTimeout:  cfg.HTTPServer.Timeout,
				WriteTimeout: cfg.HTTPServer.Timeout,
				Handler:      gen.HandlerFromMux(gen.NewStrictHandler(useCase, nil), router),
			}

			authGRPCHandlers := auth.NewAuthHandlers()
			grpcServer, err := auth.NewGRPCServer(cfg.GRPCServer.Address, authGRPCHandlers, log)
			if err != nil {
				return err
			}

			grpcCloser, err := grpcServer.Run()
			if err != nil {
				return err
			}

			go func() {
				if err = httpServer.ListenAndServe(); err != nil {
					log.Error("ListenAndServe", slog.Any("err", err))
				}
			}()
			log.Info("server listening:", slog.Any("port", cfg.HTTPServer.Address))
			<-ctx.Done()

			closeCtx, _ := context.WithTimeout(context.Background(), time.Second*5)
			if err = httpServer.Shutdown(closeCtx); err != nil {
				log.Error("httpServer.Shutdown", slog.Any("err", err))
			}

			if err = storage.Close(); err != nil {
				log.Error("storage.Close", slog.Any("err", err))
			}

			grpcCloser()

			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "path to config")
	return c
}
