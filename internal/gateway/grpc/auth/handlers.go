package auth

import (
	"context"

	"errors"

	"github.com/bogatyr285/auth-go/internal/auth/entity"
	"github.com/bogatyr285/auth-go/internal/buildinfo"
	authpb "github.com/bogatyr285/auth-go/pkg/server/grpc/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//go:generate mockgen -source=handlers.go -destination=../../../mocks/handlers_mock.go -package mock
type UserRepository interface {
	RegisterUser(ctx context.Context, u entity.UserAccount) error
	FindUserByEmail(ctx context.Context, username string) (entity.UserAccount, error)
}

//go:generate mockgen -source=handlers.go -destination=../../../mocks/handlers_mock.go -package mock
type CryptoPassword interface {
	HashPassword(password string) ([]byte, error)
	ComparePasswords(fromUser, fromDB string) bool
}

//go:generate mockgen -source=handlers.go -destination=../../../mocks/handlers_mock.go -package mock
type JWTManager interface {
	IssueAccessToken(userID string) (string, error)
	IssueRefreshToken(userID string) (string, error)
	VerifyToken(tokenString string) (*jwt.Token, error)
	RefreshTokens(refreshTokenString string) (string, string, error)
}

var ErrAccessDenied = errors.New("access_denied")

type AuthHandlers struct {
	ur UserRepository
	cp CryptoPassword
	jm JWTManager
	bi buildinfo.BuildInfo

	authpb.UnimplementedAuthServiceServer
}

func NewAuthHandlers(
	ur UserRepository,
	cp CryptoPassword,
	jm JWTManager,
	bi buildinfo.BuildInfo,
) *AuthHandlers {
	return &AuthHandlers{
		ur: ur,
		cp: cp,
		jm: jm,
		bi: bi,
	}
}

func (h *AuthHandlers) RegisterUser(ctx context.Context, req *authpb.RegisterUserRequest) (*authpb.RegisterUserResponse, error) {
	hashedPassword, err := h.cp.HashPassword(req.Password)
	if err != nil {
		// TODO dont show errs to end user. just log it
		return nil, err
	}
	// TODO with New method
	user := entity.UserAccount{
		Username: req.User.Name,
		Password: string(hashedPassword),
	}

	err = h.ur.RegisterUser(ctx, user)
	if err != nil {
		return nil, err
	}

	return &authpb.RegisterUserResponse{
		UserId:  user.Username,
		Message: "ok",
	}, nil
}

func (h *AuthHandlers) LoginUser(ctx context.Context, req *authpb.LoginUserRequest) (*authpb.LoginUserResponse, error) {
	user, err := h.ur.FindUserByEmail(ctx, req.GetEmail())
	if err != nil {
		return nil, err
	}

	if !h.cp.ComparePasswords(user.Password, req.Password) {
		return nil, status.Error(codes.Unauthenticated, ErrAccessDenied.Error())
	}

	token, err := h.jm.IssueAccessToken(user.Username)
	if err != nil {
		return nil, err
	}

	return &authpb.LoginUserResponse{
		Token: token,
	}, nil
}

func (h *AuthHandlers) UserInfo(context.Context, *authpb.UserInfoRequest) (*authpb.UserInfoResponse, error) {
	return &authpb.UserInfoResponse{
		User: &authpb.User{
			UserId: uuid.New().String(),
			ContactMethod: &authpb.User_PhoneNumber{
				PhoneNumber: "7-800-555-3535",
			},
		},
	}, nil
}
