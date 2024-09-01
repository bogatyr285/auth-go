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
	"github.com/stretchr/testify/suite"
)

type grpcGatewaySuite struct {
	suite.Suite
	cfg           *config.Config
	log           *slog.Logger
	storage       repository.SQLLiteStorage
	jwtManager    auth.JWTManager
	grpcServer    *auth.Server
	httpGwAddress string
	grpcCloser    func() error
	grpcGwCloser  func() error
}

func TestGRPCGatewaySuite(t *testing.T) {
	suite.Run(t, new(grpcGatewaySuite))
}

func (s *grpcGatewaySuite) SetupSuite() {
	var err error

	// Initialize logger
	s.log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Load configuration
	s.cfg, err = config.Parse("../../../../config.yaml")
	s.Require().NoError(err)

	// Initialize storage
	s.storage, err = repository.New(s.cfg.Storage.SQLitePath)
	s.Require().NoError(err)

	// Initialize components
	passwordHasher := crypto.NewPasswordHasher()
	s.jwtManager, err = jwt.NewJWTManager(
		s.cfg.JWT.Issuer,
		s.cfg.JWT.AccessExpiresIn,
		s.cfg.JWT.RefreshExpiresIn,
		[]byte(s.cfg.JWT.PublicKey),
		[]byte(s.cfg.JWT.PrivateKey),
		&s.storage)
	s.Require().NoError(err)

	// Set up GRPC server and Gateway
	grpcAddress := ":9090"
	s.httpGwAddress = ":9091"
	authGRPCHandlers := auth.NewAuthHandlers(&s.storage, passwordHasher, s.jwtManager, buildinfo.New())
	s.grpcServer, err = auth.NewGRPCServer(grpcAddress, authGRPCHandlers, s.log)
	s.Require().NoError(err)

	s.grpcCloser, err = s.grpcServer.Run()
	s.Require().NoError(err)

	grpcGw, err := auth.NewGateway(context.Background(), grpcAddress, s.httpGwAddress, s.log)
	s.Require().NoError(err)

	s.grpcGwCloser, err = grpcGw.Start()
	s.Require().NoError(err)
}

func (s *grpcGatewaySuite) TearDownSuite() {
	// Clean up resources
	if s.grpcCloser != nil {
		s.grpcCloser()
	}
	if s.grpcGwCloser != nil {
		s.grpcGwCloser()
	}
}

func (s *grpcGatewaySuite) TestRegisterUser() {
	registerUserReq := &authpb.RegisterUserRequest{
		User: &authpb.User{
			Name: "user1",
		},
		Password: "rLy_5tr0nG!",
	}

	registerUserReqBytes, _ := playground.ProtobufToJSON(registerUserReq)

	res, err := http.Post(fmt.Sprintf("http://localhost%s/api/v1/register", s.httpGwAddress),
		"application/json",
		bytes.NewReader(registerUserReqBytes))
	s.Require().NoError(err)
	defer res.Body.Close()

	s.Equal(http.StatusOK, res.StatusCode)

	registerResModel := &authpb.RegisterUserResponse{}
	bodyRes, err := io.ReadAll(res.Body)
	s.Require().NoError(err)

	err = json.Unmarshal(bodyRes, registerResModel)
	s.Require().NoError(err)

	s.Equal(registerResModel.UserId, registerUserReq.User.Name)
}
