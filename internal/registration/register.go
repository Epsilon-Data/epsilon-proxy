package registration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
	"github.com/Epsilon-Data/epsilon-proxy/internal/db"
)

type Registrar struct {
	apiURL     string
	httpClient *http.Client
}

type registerRequest struct {
	InstallToken string `json:"installToken"`
	Version      string `json:"version,omitempty"`
	DBType       string `json:"dbType,omitempty"`
}

type registerResponse struct {
	ProxyID        string `json:"proxyId"`
	ProxyToken     string `json:"proxyToken"`
	RatholeToken   string `json:"ratholeToken"`
	NoisePublicKey string `json:"noisePublicKey"`
	ServerAddr     string `json:"serverAddr"`
	ServiceName    string `json:"serviceName"`
	AssignedPort   int    `json:"assignedPort"`
}

func New(apiURL string) *Registrar {
	return &Registrar{
		apiURL: strings.TrimRight(apiURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (r *Registrar) Register(ctx context.Context, token string) error {
	// 1. Get DB credentials — env var or interactive prompt
	dbURL, err := getDBURL()
	if err != nil {
		return fmt.Errorf("get database credentials: %w", err)
	}

	// 2. Test DB connection
	fmt.Print("Testing database connection... ")

	// Respect sslmode if already in URL, otherwise default to "prefer"
	sslMode := "prefer"
	if strings.Contains(dbURL, "sslmode=") {
		sslMode = "" // don't override — already in URL
	}
	dbCfg := config.DatabaseConfig{
		URL:            dbURL,
		SSLMode:        sslMode,
		MaxConnections: 1,
		QueryTimeoutS:  10,
	}

	dbClient := db.New(dbCfg)
	if err := dbClient.Ping(ctx); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("database connection failed: %w", err)
	}
	fmt.Println("OK")

	// 3. Register with platform API (only sends token + version, NOT credentials)
	fmt.Print("Registering with Epsilon platform... ")

	reqBody := registerRequest{
		InstallToken: token,
		Version:      "0.1.0",
		DBType:       "postgres",
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", r.apiURL+"/proxy/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("FAILED")
		return fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	var regResp registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("parse registration response: %w", err)
	}
	fmt.Println("OK")

	// 4. Save config locally
	cfg := &config.Config{
		ProxyID:     regResp.ProxyID,
		PlatformURL: r.apiURL,
		ProxyToken:  regResp.ProxyToken,
		Rathole: config.RatholeConfig{
			ServerAddr:      regResp.ServerAddr,
			Token:           regResp.RatholeToken,
			ServiceName:     regResp.ServiceName,
			RemotePublicKey: regResp.NoisePublicKey,
		},
		Database: dbCfg,
		Server: config.ServerConfig{
			ListenAddr: "127.0.0.1:8443",
		},
	}

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println()
	fmt.Printf("Proxy ID:     %s\n", cfg.ProxyID)
	fmt.Printf("Config saved: %s\n", config.DefaultPath())
	fmt.Println("Credentials stored LOCALLY ONLY — they never leave this machine.")
	fmt.Println()
	fmt.Println("Run 'epsilon-proxy start' to connect.")

	return nil
}

// getDBURL reads the database URL from EPSILON_DB_URL env var,
// or prompts the user interactively with hidden password input.
func getDBURL() (string, error) {
	// Check env var first
	if envURL := os.Getenv("EPSILON_DB_URL"); envURL != "" {
		fmt.Println("Using database URL from EPSILON_DB_URL environment variable.")
		return envURL, nil
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("Database credentials (stored locally only, never sent to Epsilon)")
	fmt.Println("─────────────────────────────────────────────────────────────────")

	// Option: full URL or field-by-field
	fmt.Println()
	fmt.Println("Enter connection details:")
	fmt.Println("  [1] Full URL  (postgres://user:pass@host:port/dbname)")
	fmt.Println("  [2] Field-by-field")
	fmt.Print("> ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "1" {
		fmt.Print("\nDatabase URL: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(input), nil
	}

	// Field-by-field with hidden password
	fmt.Print("\nHost [localhost]: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)
	if host == "" {
		host = "localhost"
	}

	fmt.Print("Port [5432]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "5432"
	}

	fmt.Print("Database name: ")
	dbName, _ := reader.ReadString('\n')
	dbName = strings.TrimSpace(dbName)

	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	// Password with hidden input
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Println() // newline after hidden input
	password := string(passwordBytes)

	fmt.Print("SSL mode [require]: ")
	sslMode, _ := reader.ReadString('\n')
	sslMode = strings.TrimSpace(sslMode)
	if sslMode == "" {
		sslMode = "require"
	}

	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		url.QueryEscape(username),
		url.QueryEscape(password),
		host, port, dbName, sslMode)

	return dbURL, nil
}
