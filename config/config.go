package config

import (
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	HTTPServer HTTPServer `yaml:"http_server"`
	GRPCServer GRPCServer `yaml:"grpc_server"`
	Storage    Storage    `yaml:"storage"`
	JWT        JWT        `yaml:"jwt"`
}

type HTTPServer struct {
	Address string        `yaml:"address" env-default:":8080"`
	Timeout time.Duration `yaml:"timeout" env-default:"5s"`
}

type GRPCServer struct {
	Address string `yaml:"address" env-default:":9090"`
}

type Storage struct {
	SQLitePath string `yaml:"path" env-default:"db.sqlite"`
}

type JWT struct {
	Issuer     string        `yaml:"issuer"`
	ExpiresIn  time.Duration `yaml:"expires_in"`
	PublicKey  string        `yaml:"public_key"`
	PrivateKey string        `yaml:"private_key"`
}

func Parse(s string) (*Config, error) {
	c := &Config{}
	if err := cleanenv.ReadConfig(s, c); err != nil {
		return nil, err
	}

	privateKey, err := os.ReadFile(c.JWT.PrivateKey)
	if err != nil {
		return nil, err
	}

	publicKey, err := os.ReadFile(c.JWT.PublicKey)
	if err != nil {
		return nil, err
	}

	c.JWT.PrivateKey = string(privateKey)
	c.JWT.PublicKey = string(publicKey)

	return c, nil
}
