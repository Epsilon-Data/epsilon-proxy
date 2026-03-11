package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ProxyID     string            `yaml:"proxy_id"`
	DatasetID   string            `yaml:"dataset_id"`
	PlatformURL string            `yaml:"platform_url"`
	ProxyToken  string            `yaml:"proxy_token"`
	DevMode     bool              `yaml:"dev_mode"`
	Rathole     RatholeConfig     `yaml:"rathole"`
	Database    DatabaseConfig    `yaml:"database"`
	Server      ServerConfig      `yaml:"server"`
	Attestation AttestationConfig `yaml:"attestation"`
}

type RatholeConfig struct {
	ServerAddr      string `yaml:"server_addr"`
	Token           string `yaml:"token"`
	ServiceName     string `yaml:"service_name"`
	RemotePublicKey string `yaml:"remote_public_key"`
}

type DatabaseConfig struct {
	URL            string `yaml:"url"`
	SSLMode        string `yaml:"ssl_mode"`
	MaxConnections int    `yaml:"max_connections"`
	QueryTimeoutS  int    `yaml:"query_timeout_s"`
}

func (d DatabaseConfig) Host() string {
	u, err := url.Parse(d.URL)
	if err != nil {
		return "unknown"
	}
	return u.Hostname()
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type AttestationConfig struct {
	ExpectedPCR0 string `yaml:"expected_pcr0"`
}

func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".epsilon-proxy", "config.yaml")
}

func PidPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".epsilon-proxy", "proxy.pid")
}

func WritePid() error {
	path := PidPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d", os.Getpid())), 0600)
}

func RemovePid() {
	os.Remove(PidPath())
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.setDefaults()
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = "127.0.0.1:8443"
	}
	if c.Database.MaxConnections == 0 {
		c.Database.MaxConnections = 5
	}
	if c.Database.QueryTimeoutS == 0 {
		c.Database.QueryTimeoutS = 120
	}
	if c.Database.SSLMode == "" {
		c.Database.SSLMode = "require"
	}
}

func Save(cfg *Config) error {
	path := DefaultPath()
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

func Remove() error {
	path := DefaultPath()
	dir := filepath.Dir(path)
	return os.RemoveAll(dir)
}
