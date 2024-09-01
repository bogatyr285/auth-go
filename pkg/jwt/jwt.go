package jwt

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// for now there's no reason for err segregation & uniq processing
	// but its good idea to have list of error which module can return
	ErrKeyParsing       = fmt.Errorf("parsing error")
	ErrTokenGeneration  = fmt.Errorf("token generation error")
	ErrSigning          = fmt.Errorf("signing error")
	ErrValidation       = fmt.Errorf("token validation errror")
	ErrInvalidTokenType = fmt.Errorf("invalid token type")
	ErrRefreshTokenExp  = fmt.Errorf("refresh token expired")
)

type JWTRefreshTokenRepository interface {
	StoreRefreshToken(token string, userID string, issuedAt, expiresAt time.Time) error
	IsRefreshTokenValid(token string) (bool, string, error)
	RevokeRefreshToken(token string) error
}

type JWTManager struct {
	issuer           string
	accessExpiresIn  time.Duration
	refreshExpiresIn time.Duration
	publicKey        interface{}
	privateKey       interface{}
	db               JWTRefreshTokenRepository
}

func NewJWTManager(issuer string, accessExpiresIn time.Duration, refreshExpiresIn time.Duration, publicKey, privateKey []byte, db JWTRefreshTokenRepository) (*JWTManager, error) {
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}
	// TODO use Ed algs

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	return &JWTManager{
		issuer:           issuer,
		accessExpiresIn:  accessExpiresIn,
		refreshExpiresIn: refreshExpiresIn,
		publicKey:        pubKey,
		privateKey:       privKey,
		db:               db,
	}, nil
}

func (j *JWTManager) IssueAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"iss":  j.issuer,
		"sub":  userID,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(j.accessExpiresIn).Unix(),
		"type": "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(j.privateKey.(*rsa.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSigning, err)
	}
	return signed, nil
}

func (j *JWTManager) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrValidation
		}
		return j.publicKey, nil
	},
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, err)
	}

	return token, nil
}

func (j *JWTManager) IssueRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"iss":  j.issuer,
		"sub":  userID,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(j.refreshExpiresIn).Unix(),
		"type": "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(j.privateKey.(*rsa.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSigning, err)
	}

	err = j.db.StoreRefreshToken(signed, userID, time.Now(), time.Now().Add(j.refreshExpiresIn))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrTokenGeneration, err)
	}

	return signed, nil
}

func (j *JWTManager) RefreshTokens(refreshTokenString string) (string, string, error) {
	valid, userID, err := j.db.IsRefreshTokenValid(refreshTokenString)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", ErrValidation, err)
	}
	if !valid {
		return "", "", ErrRefreshTokenExp
	}

	token, err := j.VerifyToken(refreshTokenString)
	if err != nil {
		return "", "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "refresh" {
		return "", "", ErrInvalidTokenType
	}

	newAccessToken, err := j.IssueAccessToken(userID)
	if err != nil {
		return "", "", err
	}
	newRefreshToken, err := j.IssueRefreshToken(userID)
	if err != nil {
		return "", "", err
	}

	err = j.db.RevokeRefreshToken(refreshTokenString)
	if err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}