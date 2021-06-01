package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	clientJWTLifetime                  = 5 * time.Minute
	downstreamAuthorizationJWTLifetime = 30 * time.Second
)

type ClientClaims struct {
	CodeChallenge string `json:"code_challenge"`
	State         string `json:"state"`
	RedirectURI   string `json:"redirect_uri"`
	jwt.StandardClaims
}

type AuthorizationCodeClaims struct {
	AuthorizationCode string `json:"authorization_code"`
	CodeChallenge     string `json:"code_challenge"`
	jwt.StandardClaims
}

func ClientClaimsToJWT(challenge, state, redirectURI string) (string, error) {
	encChallenge, err := encrypt(challenge, config.EncryptionKey)
	if err != nil {
		return "", err
	}

	claims := ClientClaims{
		CodeChallenge: string(encChallenge),
		State:         state,
		RedirectURI:   redirectURI,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(clientJWTLifetime).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(config.JWT.SigningKey)
}

func ParseClientClaims(tokenStr string) (*ClientClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &ClientClaims{}, func(token *jwt.Token) (interface{}, error) {
		return config.JWT.SigningKey, nil
	})

	if err != nil {
		return nil, err
	} else if !token.Valid {
		return nil, errors.New("invalid token")

	}

	claims, ok := token.Claims.(*ClientClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

func AuthorizationCodeClaimsToJWT(challenge, code string) (string, error) {
	encCode, err := encrypt(code, config.EncryptionKey)
	if err != nil {
		return "", err
	}

	claims := AuthorizationCodeClaims{
		CodeChallenge:     challenge,
		AuthorizationCode: string(encCode),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(downstreamAuthorizationJWTLifetime).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(config.JWT.SigningKey)
}

func ParseAuthorizationCodeClaims(tokenStr string) (challenge, code string, err error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AuthorizationCodeClaims{}, func(token *jwt.Token) (interface{}, error) {
		return config.JWT.SigningKey, nil
	})

	if err != nil {
		return "", "", err
	} else if !token.Valid {
		return "", "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(*AuthorizationCodeClaims)
	if !ok {
		return "", "", errors.New("invalid token claims")
	}

	challenge, err = decrypt(claims.CodeChallenge, config.EncryptionKey)
	if err != nil {
		return "", "", err
	}

	code, err = decrypt(claims.AuthorizationCode, config.EncryptionKey)
	if err != nil {
		return "", "", err
	}

	return
}

func encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)

	nonce := make([]byte, aesGCM.NonceSize())

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(enc string, key []byte) (string, error) {
	encBytes, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()

	nonce, ciphertext := encBytes[:nonceSize], encBytes[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
