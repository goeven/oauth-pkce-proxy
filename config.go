package main

import (
	"log"

	"github.com/kelseyhightower/envconfig"
)

var config Config

type Config struct {
	Port int `envconfig:"port"`

	Oauth OauthConfig `envconfig:"oauth"`

	JWT JWTConfig `envconfig:"jwt"`

	EncryptionKey []byte `envconfig:"encryption_key"`
}

type OauthConfig struct {
	ClientID     string `envconfig:"client_id"`
	ClientSecret string `envconfig:"client_secret"`
	AuthURL      string `envconfig:"auth_url"`
	TokenURL     string `envconfig:"token_url"`
	RedirectURL  string `envconfig:"redirect_url"`
}

type JWTConfig struct {
	SigningKey []byte `envconfig:"signing_key"`
}

func init() {
	envconfig.MustProcess("", &config)

	if string(config.EncryptionKey) == "" {
		log.Fatal("The encryption key must not be empty")
	}

	if string(config.JWT.SigningKey) == "" {
		log.Fatal("The JWT signing key must not be empty")
	}
}
