package config

import (
	"encoding/hex"
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
	Version     string            `yaml:"-"` // set at runtime via ldflags, not persisted
	DevMode     bool              `yaml:"dev_mode"`
	Rathole     RatholeConfig     `yaml:"rathole"`
	Database    DatabaseConfig    `yaml:"database"`
	Server      ServerConfig      `yaml:"server"`
	Attestation AttestationConfig `yaml:"attestation"`
	// ReleaseLogPath is the file that gets one line per data release.
	ReleaseLogPath string `yaml:"release_log_path"`
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

// PCR0HexLength is the length of a PCR0 value in hex: a SHA-384 digest.
const PCR0HexLength = 96

type AttestationConfig struct {
	// ExpectedPCR0 is the measurement of the only enclave image this proxy releases data to.
	ExpectedPCR0 string `yaml:"expected_pcr0"`
	// MaxAgeS is how old an attestation document may be when it is presented, in seconds.
	MaxAgeS int `yaml:"max_age_s"`
}

// ValidatePCR0 checks that value is a full PCR0 measurement (96 hex characters).
func ValidatePCR0(value string) error {
	if value == "" {
		return fmt.Errorf("expected PCR0 is not set")
	}
	if len(value) != PCR0HexLength {
		return fmt.Errorf("expected PCR0 must be %d hex characters, got %d", PCR0HexLength, len(value))
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("expected PCR0 is not hex: %w", err)
	}
	return nil
}

func DefaultReleaseLogPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".epsilon-proxy", "releases.log")
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
	if c.Attestation.MaxAgeS == 0 {
		c.Attestation.MaxAgeS = 300
	}
	if c.ReleaseLogPath == "" {
		c.ReleaseLogPath = DefaultReleaseLogPath()
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

// Remove deletes the local config and PID file. The release log is kept: it is the
// custodian's record of what was released and outlives a registration.
func Remove() error {
	RemovePid()
	if err := os.Remove(DefaultPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
