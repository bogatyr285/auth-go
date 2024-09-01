package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bogatyr285/auth-go/internal/auth/entity"
	"github.com/bogatyr285/auth-go/internal/buildinfo"
	"github.com/bogatyr285/auth-go/internal/gateway/grpc/auth"
	"github.com/bogatyr285/auth-go/internal/mocks"
	authpb "github.com/bogatyr285/auth-go/pkg/server/grpc/auth"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLoginUser(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockCryptoPassword := mocks.NewMockCryptoPassword(ctrl)
	mockJWTManager := mocks.NewMockJWTManager(ctrl)

	type args struct {
		ctx context.Context
		req *authpb.LoginUserRequest
	}
	tests := []struct {
		name             string
		args             args
		setupMocks       func()
		expectedResponse *authpb.LoginUserResponse
		expectedError    error
	}{
		{
			name: "successful login",
			args: args{
				ctx: context.Background(),
				req: &authpb.LoginUserRequest{
					LoginMethod: &authpb.LoginUserRequest_Email{Email: "test@example.com11"},
					Password:    "validpassword",
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByEmail(gomock.Any(), "test@example.com").
					Return(entity.UserAccount{Username: "user1", Password: "hashedpassword"}, nil)

				mockCryptoPassword.EXPECT().
					ComparePasswords("hashedpassword", "validpassword").
					Return(true)

				mockJWTManager.EXPECT().
					IssueAccessToken("user1").
					Return("validtoken", nil)
			},
			expectedResponse: &authpb.LoginUserResponse{
				Token: "validtoken",
			},
			expectedError: nil,
		},
		{
			name: "user not found",
			args: args{
				ctx: context.Background(),
				req: &authpb.LoginUserRequest{
					LoginMethod: &authpb.LoginUserRequest_Email{Email: "nonexistent@example.com"},
					Password:    "password",
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByEmail(gomock.Any(), "nonexistent@example.com").
					Return(entity.UserAccount{}, errors.New("not found"))

				// Other mocks won't get called
			},
			expectedResponse: nil,
			expectedError:    errors.New("not found"),
		},
		{
			name: "incorrect password",
			args: args{
				ctx: context.Background(),
				req: &authpb.LoginUserRequest{
					LoginMethod: &authpb.LoginUserRequest_Email{Email: "test@example.com"},
					Password:    "wrongpassword",
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByEmail(gomock.Any(), "test@example.com").
					Return(entity.UserAccount{Username: "user1", Password: "hashedpassword"}, nil)

				mockCryptoPassword.EXPECT().
					ComparePasswords("hashedpassword", "wrongpassword").
					Return(false)

				// JWTManager mock should not be called
			},
			expectedResponse: nil,
			expectedError:    status.Error(codes.Unauthenticated, auth.ErrAccessDenied.Error()),
		},
		{
			name: "token issuance failure",
			args: args{
				ctx: context.Background(),
				req: &authpb.LoginUserRequest{
					LoginMethod: &authpb.LoginUserRequest_Email{Email: "test@example.com"},
					Password:    "validpassword",
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByEmail(gomock.Any(), "test@example.com").
					Return(entity.UserAccount{Username: "user1", Password: "hashedpassword"}, nil)

				mockCryptoPassword.EXPECT().
					ComparePasswords("hashedpassword", "validpassword").
					Return(true)

				mockJWTManager.EXPECT().
					IssueAccessToken("user1").
					Return("", errors.New("token issuance error"))
			},
			expectedResponse: nil,
			expectedError:    errors.New("token issuance error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := auth.NewAuthHandlers(
				mockUserRepo,
				mockCryptoPassword,
				mockJWTManager,
				buildinfo.BuildInfo{},
			)
			tt.setupMocks()
			resp, err := h.LoginUser(tt.args.ctx, tt.args.req)

			assert.Equal(t, tt.expectedResponse, resp)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}
