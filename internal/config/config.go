package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Gateway     GatewayConfig     `yaml:"gateway"`
	TLS         TLSConfig         `yaml:"tls"`
	JWT         JWTConfig         `yaml:"jwt"`
	Logging     LoggingConfig     `yaml:"logging"`
	RateLimit   RateLimitConfig   `yaml:"rate_limit"`
}

type GatewayConfig struct {
	ListenAddr   string `yaml:"listen_addr"`
	BackendAddr  string `yaml:"backend_addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type TLSConfig struct {
	CACertFile     string `yaml:"ca_cert_file"`
	ServerCertFile string `yaml:"server_cert_file"`
	ServerKeyFile  string `yaml:"server_key_file"`
	// ClientAuth enforces mTLS — always require client cert
	ClientAuth string `yaml:"client_auth"` // "require" | "verify"
}

type JWTConfig struct {
	SigningKeyFile string        `yaml:"signing_key_file"`
	Issuer        string        `yaml:"issuer"`
	TokenTTL      time.Duration `yaml:"token_ttl"`
}

type LoggingConfig struct {
	Level   string `yaml:"level"` // "debug" | "info" | "warn" | "error"
	Output  string `yaml:"output"` // "stdout" | file path
	Format  string `yaml:"format"` // "json" (default) | "text"
}

type RateLimitConfig struct {
	MaxFailuresPerMin int           `yaml:"max_failures_per_min"`
	BanDuration       time.Duration `yaml:"ban_duration"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.setDefaults()
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Gateway.ListenAddr == "" {
		c.Gateway.ListenAddr = ":8443"
	}
	if c.Gateway.ReadTimeout == 0 {
		c.Gateway.ReadTimeout = 30 * time.Second
	}
	if c.Gateway.WriteTimeout == 0 {
		c.Gateway.WriteTimeout = 30 * time.Second
	}
	if c.JWT.Issuer == "" {
		c.JWT.Issuer = "iot-auth-gateway"
	}
	if c.JWT.TokenTTL == 0 {
		c.JWT.TokenTTL = 1 * time.Hour
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
	if c.RateLimit.MaxFailuresPerMin == 0 {
		c.RateLimit.MaxFailuresPerMin = 10
	}
	if c.RateLimit.BanDuration == 0 {
		c.RateLimit.BanDuration = 15 * time.Minute
	}
}
