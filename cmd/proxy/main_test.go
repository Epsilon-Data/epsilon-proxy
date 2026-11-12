package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
)

func servableConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ProxyToken:     "pt",
		Attestation:    config.AttestationConfig{ExpectedPCR0: strings.Repeat("ab", 48)},
		ReleaseLogPath: filepath.Join(t.TempDir(), "releases.log"),
	}
}

func TestCheckServable(t *testing.T) {
	if err := checkServable(servableConfig(t)); err != nil {
		t.Fatalf("complete config refused: %v", err)
	}

	noPCR0 := servableConfig(t)
	noPCR0.Attestation.ExpectedPCR0 = ""
	if err := checkServable(noPCR0); err == nil {
		t.Error("config without expected_pcr0 was accepted")
	}

	shortPCR0 := servableConfig(t)
	shortPCR0.Attestation.ExpectedPCR0 = "abab"
	if err := checkServable(shortPCR0); err == nil {
		t.Error("config with a truncated expected_pcr0 was accepted")
	}

	noLog := servableConfig(t)
	noLog.ReleaseLogPath = ""
	if err := checkServable(noLog); err == nil {
		t.Error("config without a release log was accepted")
	}

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	unwritable := servableConfig(t)
	unwritable.ReleaseLogPath = filepath.Join(blocker, "releases.log")
	if err := checkServable(unwritable); err == nil {
		t.Error("config with an unwritable release log was accepted")
	}
}

func TestStartExitsWithAnErrorWithoutAnExpectedPCR0(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("proxy_token: pt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	cmd := startCmd()
	cmd.SetArgs([]string{"--config", path})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "expected PCR0 is not set") {
		t.Fatalf("err = %v, want the missing expected PCR0", err)
	}
}

func TestRegisterRefusesBeforeTouchingTheConfigWithoutAValidPCR0(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := config.Save(&config.Config{ProxyID: "px-existing"}); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"--token", "ept_x"},
		{"--token", "ept_x", "--expected-pcr0", "abab"},
	} {
		cmd := registerCmd()
		cmd.SetArgs(args)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--expected-pcr0") {
			t.Fatalf("args %v: err = %v, want an --expected-pcr0 error", args, err)
		}
	}

	if _, err := os.Stat(config.DefaultPath()); err != nil {
		t.Fatalf("existing config was removed: %v", err)
	}
}
