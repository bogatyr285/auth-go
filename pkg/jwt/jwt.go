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
	ErrKeyParsing      = fmt.Errorf("parsing error")
	ErrTokenGeneration = fmt.Errorf("token generation error")
	ErrSigning         = fmt.Errorf("signing error")
	ErrValidation      = fmt.Errorf("token validation errror")
)

type JWTManager struct {
	issuer     string
	expiresIn  time.Duration
	publicKey  interface{}
	privateKey interface{}
}

func NewJWTManager(issuer string, expiresIn time.Duration, publicKey, privateKey []byte) (*JWTManager, error) {
	pubKey, err := jwt.ParseEdPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	privKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	return &JWTManager{
		issuer:     issuer,
		expiresIn:  expiresIn,
		publicKey:  pubKey,
		privateKey: privKey,
	}, nil
}

func (j *JWTManager) IssueToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"iss": j.issuer,
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(j.expiresIn).Unix(),
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
