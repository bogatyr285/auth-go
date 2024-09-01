package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/bogatyr285/auth-go/config"
	"github.com/bogatyr285/auth-go/internal/auth/repository"
	"github.com/bogatyr285/auth-go/internal/buildinfo"
	"github.com/bogatyr285/auth-go/internal/gateway/grpc/auth"
	"github.com/bogatyr285/auth-go/pkg/crypto"
	"github.com/bogatyr285/auth-go/pkg/jwt"
	authpb "github.com/bogatyr285/auth-go/pkg/server/grpc/auth"
	"github.com/bogatyr285/auth-go/playground"
	"github.com/stretchr/testify/assert"
)

func TestGRPCGateway(t *testing.T) {
	// configure
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := config.Parse("../../../../config.yaml")
	assert.NoError(t, err)

	storage, err := repository.New(cfg.Storage.SQLitePath)
	assert.NoError(t, err)

	passwordHasher := crypto.NewPasswordHasher()
	jwtManager, err := jwt.NewJWTManager(
		cfg.JWT.Issuer,
		cfg.JWT.AccessExpiresIn,
		cfg.JWT.RefreshExpiresIn,
		[]byte(cfg.JWT.PublicKey),
		[]byte(cfg.JWT.PrivateKey),
		&storage)
	assert.NoError(t, err)

	grpcAddress := ":9090"
	httpGwAddress := ":9091"
	authGRPCHandlers := auth.NewAuthHandlers(&storage, passwordHasher, jwtManager, buildinfo.New())
	grpcServer, err := auth.NewGRPCServer(grpcAddress, authGRPCHandlers, log)
	assert.NoError(t, err)

	grpcCloser, err := grpcServer.Run()
	assert.NoError(t, err)
	defer grpcCloser()

	grpcGw, err := auth.NewGateway(context.Background(), grpcAddress, httpGwAddress, log)
	assert.NoError(t, err)

	grpcGwCloser, err := grpcGw.Start()
	assert.NoError(t, err)
	defer grpcGwCloser()

	// prepare
	registerUserReq := &authpb.RegisterUserRequest{
		User: &authpb.User{
			Name: "user1",
		},
		Password: "rLy_5tr0nG!",
	}

	registerUserReqBytes, _ := playground.ProtobufToJSON(registerUserReq)

	// act
	res, err := http.Post(fmt.Sprintf("http://localhost%s/api/v1/register", httpGwAddress),
		"application/json",
		bytes.NewReader(registerUserReqBytes))
	assert.NoError(t, err)

	assert.Equal(t, res.StatusCode, http.StatusOK)

	// check
	registerResModel := &authpb.RegisterUserResponse{}
	bodyRes, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	json.Unmarshal(bodyRes, registerResModel)

	assert.Equal(t, registerResModel.UserId, registerUserReq.User.Name)
}
