package tunnel

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
)

const configTemplate = `[client]
remote_addr = "{{ .ServerAddr }}"
{{ if .RemotePublicKey }}
[client.transport]
type = "noise"

[client.transport.noise]
remote_public_key = "{{ .RemotePublicKey }}"
{{ end }}
[client.services.{{ .ServiceName }}]
token = "{{ .Token }}"
local_addr = "127.0.0.1:8443"
`

type Manager struct {
	cfg    config.RatholeConfig
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func New(cfg config.RatholeConfig) *Manager {
	return &Manager{cfg: cfg}
}

// Start spawns the rathole client subprocess.
func (m *Manager) Start(ctx context.Context) error {
	configPath, err := m.writeConfig()
	if err != nil {
		return fmt.Errorf("write rathole config: %w", err)
	}

	// Find rathole binary
	ratholeBin, err := findRathole()
	if err != nil {
		return fmt.Errorf("rathole binary not found: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	go m.runWithRestart(ctx, ratholeBin, configPath)

	return nil
}

// Stop terminates the rathole subprocess.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Kill()
	}
}

func (m *Manager) runWithRestart(ctx context.Context, bin, configPath string) {
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		m.cmd = exec.CommandContext(ctx, bin, "--client", configPath)
		m.cmd.Stdout = os.Stdout
		m.cmd.Stderr = os.Stderr

		log.Printf("[TUNNEL] Starting rathole client → %s", m.cfg.ServerAddr)

		err := m.cmd.Run()
		if ctx.Err() != nil {
			return // Context cancelled, intentional shutdown
		}

		log.Printf("[TUNNEL] rathole exited: %v, restarting in %v", err, backoff)
		time.Sleep(backoff)

		// Exponential backoff capped at 30s
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (m *Manager) writeConfig() (string, error) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".epsilon-proxy")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	path := filepath.Join(dir, "rathole-client.toml")

	tmpl, err := template.New("rathole").Parse(configTemplate)
	if err != nil {
		return "", err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := tmpl.Execute(f, m.cfg); err != nil {
		return "", err
	}

	return path, nil
}

func findRathole() (string, error) {
	// Check in PATH
	if path, err := exec.LookPath("rathole"); err == nil {
		return path, nil
	}

	// Check next to our binary
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	candidate := filepath.Join(exeDir, "rathole")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Check in config dir
	home, _ := os.UserHomeDir()
	candidate = filepath.Join(home, ".epsilon-proxy", "rathole")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	return "", fmt.Errorf("rathole binary not found in PATH, %s, or %s", exeDir, filepath.Join(home, ".epsilon-proxy"))
}
