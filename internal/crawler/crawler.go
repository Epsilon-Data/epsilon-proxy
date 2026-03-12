package crawler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
)

const (
	tblsBinary     = "tbls"
	crawlTimeout   = 120 * time.Second
	uploadTimeout  = 30 * time.Second
)

type metadataUpload struct {
	ProxyToken string                 `json:"proxyToken"`
	Schema     map[string]interface{} `json:"schema"`
	ERD        string                 `json:"erd"`
	DBType     string                 `json:"dbType,omitempty"`
}

// Run executes tbls to crawl the database schema, then uploads metadata to the platform API.
func Run(ctx context.Context, cfg *config.Config) error {
	log.Println("[crawler] Starting database schema crawl...")

	// Check tbls is installed
	if _, err := exec.LookPath(tblsBinary); err != nil {
		return fmt.Errorf("tbls not found in PATH: %w (install with: go install github.com/k1LoW/tbls@latest)", err)
	}

	// Create temp dir for tbls output
	tmpDir, err := os.MkdirTemp("", "epsilon-crawl-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	schemaPath := filepath.Join(tmpDir, "schema.json")
	erdPath := filepath.Join(tmpDir, "erd.md")

	// Build the DSN for tbls (it uses the standard postgres:// URL)
	dsn := cfg.Database.URL
	if cfg.Database.SSLMode != "" && !strings.Contains(dsn, "sslmode=") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "sslmode=" + cfg.Database.SSLMode
	}

	// Step 1: Run tbls to get JSON schema
	crawlCtx, cancel := context.WithTimeout(ctx, crawlTimeout)
	defer cancel()

	log.Println("[crawler] Running tbls out (JSON schema)...")
	schemaCmd := exec.CommandContext(crawlCtx, tblsBinary, "out", dsn, "--format", "json", "--out", schemaPath)
	schemaCmd.Stderr = os.Stderr
	if err := schemaCmd.Run(); err != nil {
		return fmt.Errorf("tbls schema crawl failed: %w", err)
	}

	// Step 2: Run tbls to get ERD (Mermaid format)
	log.Println("[crawler] Running tbls out (ERD)...")
	erdCmd := exec.CommandContext(crawlCtx, tblsBinary, "out", dsn, "--format", "mermaid", "--out", erdPath)
	erdCmd.Stderr = os.Stderr
	if err := erdCmd.Run(); err != nil {
		// ERD is optional — log warning but continue
		log.Printf("[crawler] WARNING: tbls ERD generation failed: %v (continuing without ERD)", err)
	}

	// Read the output files
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema output: %w", err)
	}

	var schemaJSON map[string]interface{}
	if err := json.Unmarshal(schemaData, &schemaJSON); err != nil {
		return fmt.Errorf("parse schema JSON: %w", err)
	}

	erdData := ""
	if data, err := os.ReadFile(erdPath); err == nil {
		erdData = string(data)
	}

	log.Printf("[crawler] Schema crawled successfully (%d bytes, ERD: %d bytes)", len(schemaData), len(erdData))

	// Step 3: Upload to platform API
	return upload(ctx, cfg, schemaJSON, erdData)
}

func upload(ctx context.Context, cfg *config.Config, schema map[string]interface{}, erd string) error {
	log.Println("[crawler] Uploading metadata to platform...")

	payload := metadataUpload{
		ProxyToken: cfg.ProxyToken,
		Schema:     schema,
		ERD:        erd,
		DBType:     "postgres",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	uploadCtx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/proxy/metadata", cfg.PlatformURL)
	req, err := http.NewRequestWithContext(uploadCtx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: uploadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed: HTTP %d", resp.StatusCode)
	}

	log.Println("[crawler] Metadata uploaded successfully")
	return nil
}

