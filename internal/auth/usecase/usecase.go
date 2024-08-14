package usecase

import (
	"context"
	"github.com/google/uuid"
	"github.com/labstack/gommon/log"
	"net/http"
	"strings"

	"github.com/bogatyr285/auth-go/internal/auth/entity"
	"github.com/bogatyr285/auth-go/internal/buildinfo"
	"github.com/bogatyr285/auth-go/internal/gateway/http/gen"
	"github.com/golang-jwt/jwt/v5"
)

type UserRepository interface {
	RegisterUser(ctx context.Context, u entity.UserAccount) error
	FindUserByEmail(ctx context.Context, username string) (entity.UserAccount, error)
	GetUserById(ctx context.Context, ID int) (entity.UserAccount, error)
	GenerateUserToken(ctx context.Context, userID int) (uuid.UUID, error)
	ExistsToken(ctx context.Context, token string) (bool, error)
	SelectUserByToken(ctx context.Context, token string) (entity.UserAccount, error)
	ExistsUserByUsername(ctx context.Context, username string) (bool, error)
}

type CryptoPassword interface {
	HashPassword(password string) ([]byte, error)
	ComparePasswords(fromUser, fromDB string) bool
}

type JWTManager interface {
	IssueToken(userID string) (string, error)
	VerifyToken(tokenString string) (*jwt.Token, error)
}

type AuthUseCase struct {
	ur UserRepository
	cp CryptoPassword
	jm JWTManager
	bi buildinfo.BuildInfo
}

func (u AuthUseCase) PostRefresh(ctx context.Context, request gen.PostRefreshRequestObject) (gen.PostRefreshResponseObject, error) {
	exists, err := u.ur.ExistsToken(ctx, request.Body.RefreshToken)
	if err != nil {
		return gen.PostRefresh500JSONResponse{}, nil
	}

	if !exists {
		return gen.PostRefresh500JSONResponse{}, nil
	}

	user, err := u.ur.SelectUserByToken(ctx, request.Body.RefreshToken)
	if err != nil {
		return gen.PostRefresh500JSONResponse{}, nil
	}

	token, err := u.jm.IssueToken(user.Username)
	if err != nil {
		return gen.PostRefresh500JSONResponse{}, err
	}

	return gen.PostRefresh200JSONResponse{
		AccessToken:  token,
		RefreshToken: request.Body.RefreshToken,
	}, nil
}

func (u AuthUseCase) GetUsersId(ctx context.Context, request gen.GetUsersIdRequestObject) (gen.GetUsersIdResponseObject, error) {
	if request.Id == 0 {
		return gen.GetUsersId500JSONResponse{}, nil
	}

	user, err := u.ur.GetUserById(ctx, request.Id)
	if err != nil {
		return gen.GetUsersId500JSONResponse{}, nil
	}

	return gen.GetUsersId200JSONResponse{
		Username: user.Username,
	}, nil
}

func NewUseCase(ur UserRepository, cp CryptoPassword, jm JWTManager, bi buildinfo.BuildInfo) AuthUseCase {
	return AuthUseCase{
		ur: ur,
		cp: cp,
		jm: jm,
		bi: bi,
	}
}

func (u AuthUseCase) PostLogin(ctx context.Context, request gen.PostLoginRequestObject) (gen.PostLoginResponseObject, error) {
	user, err := u.ur.FindUserByEmail(ctx, request.Body.Username)
	if err != nil {
		return gen.PostLogin500JSONResponse{
			Error: err.Error(),
		}, nil
	}

	if !u.cp.ComparePasswords(user.Password, request.Body.Password) {
		return gen.PostLogin401JSONResponse{Error: "unauth"}, nil
	}

	token, err := u.jm.IssueToken(user.Username)
	if err != nil {
		return gen.PostLogin500JSONResponse{}, err
	}

	refreshToken, err := u.ur.GenerateUserToken(ctx, user.ID)
	if err != nil {
		return gen.PostLogin500JSONResponse{}, err
	}

	return gen.PostLogin200JSONResponse{
		AccessToken:  token,
		RefreshToken: refreshToken.String(),
	}, nil
}

func (u AuthUseCase) PostRegister(ctx context.Context, request gen.PostRegisterRequestObject) (gen.PostRegisterResponseObject, error) {
	hashedPassword, err := u.cp.HashPassword(request.Body.Password)
	if err != nil {
		return gen.PostRegister500JSONResponse{}, nil
	}

	user := entity.UserAccount{
		Username: request.Body.Username,
		Password: string(hashedPassword),
	}

	err = u.ur.RegisterUser(ctx, user)
	if err != nil {
		return gen.PostRegister500JSONResponse{}, nil
	}
	return gen.PostRegister201JSONResponse{
		Username: request.Body.Username,
	}, nil
}

func (u AuthUseCase) GetBuildinfo(ctx context.Context, request gen.GetBuildinfoRequestObject) (gen.GetBuildinfoResponseObject, error) {
	return gen.GetBuildinfo200JSONResponse{
		Arch:       u.bi.Arch,
		BuildDate:  u.bi.BuildDate,
		CommitHash: u.bi.CommitHash,
		Compiler:   u.bi.Compiler,
		GoVersion:  u.bi.GoVersion,
		Os:         u.bi.OS,
		Version:    u.bi.Version,
	}, nil
}

func (u AuthUseCase) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
			return
		}

		// Bearer <token>
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Errorf("Invalid Authorization header format: %s", authHeader)
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		verifyToken, err := u.jm.VerifyToken(tokenString)
		if err != nil {
			log.Errorf("Failed to verify token: %s", err)
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		claims := verifyToken.Claims.(jwt.MapClaims)
		exists, err := u.ur.ExistsUserByUsername(r.Context(), claims["username"].(string))
		if err != nil {
			log.Errorf("Failed to verify token: %s", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !exists {
			log.Errorf("User not found: %s", claims["username"].(string))
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}
