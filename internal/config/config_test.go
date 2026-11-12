package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePCR0(t *testing.T) {
	if err := ValidatePCR0(strings.Repeat("ab", 48)); err != nil {
		t.Fatalf("full PCR0 refused: %v", err)
	}
	for name, value := range map[string]string{
		"empty":     "",
		"truncated": strings.Repeat("ab", 8),
		"too long":  strings.Repeat("ab", 49),
		"not hex":   strings.Repeat("zz", 48),
	} {
		if err := ValidatePCR0(value); err == nil {
			t.Errorf("%s PCR0 was accepted", name)
		}
	}
}

func TestLoadDefaultsTheReleaseLogAndKeepsTheExpectedPCR0(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	pcr0 := strings.Repeat("ab", 48)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("proxy_token: pt\nattestation:\n  expected_pcr0: "+pcr0+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Attestation.ExpectedPCR0 != pcr0 {
		t.Fatalf("expected_pcr0 = %q", cfg.Attestation.ExpectedPCR0)
	}
	if cfg.ReleaseLogPath != DefaultReleaseLogPath() {
		t.Fatalf("release_log_path = %q, want %q", cfg.ReleaseLogPath, DefaultReleaseLogPath())
	}
}

func TestRemoveKeepsTheReleaseLog(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := Save(&Config{ProxyID: "px-1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(DefaultReleaseLogPath(), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	// Removing an already removed config is not an error
	if err := Remove(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(DefaultPath()); !os.IsNotExist(err) {
		t.Fatalf("config still exists: %v", err)
	}
	if _, err := os.Stat(DefaultReleaseLogPath()); err != nil {
		t.Fatalf("release log was removed: %v", err)
	}
}
