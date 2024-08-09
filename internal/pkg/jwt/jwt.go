package jwt

import (
	"crypto/ed25519"
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
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func NewJWTManager(issuer string, expiresIn time.Duration, publicKey, privateKey []byte) (*JWTManager, error) {
	pubKey := ed25519.PublicKey(publicKey)
	privKey := ed25519.PrivateKey(privateKey)

	// Проверка корректности ключей
	if len(pubKey) != ed25519.PublicKeySize || len(privKey) != ed25519.PrivateKeySize {
		return nil, ErrKeyParsing
	}

	return &JWTManager{
		issuer:     issuer,
		expiresIn:  expiresIn,
		publicKey:  pubKey,
		privateKey: privKey,
	}, nil
}

func (j *JWTManager) IssueToken(userID string) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    j.issuer,
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.expiresIn)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	signed, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSigning, err)
	}
	return signed, nil
}

func (j *JWTManager) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrValidation
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, err)
	}

	return token, nil
}
