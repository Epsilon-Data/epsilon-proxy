package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
	"github.com/Epsilon-Data/epsilon-proxy/internal/db"
	"github.com/Epsilon-Data/epsilon-proxy/internal/heartbeat"
	"github.com/Epsilon-Data/epsilon-proxy/internal/registration"
	"github.com/Epsilon-Data/epsilon-proxy/internal/server"
	"github.com/Epsilon-Data/epsilon-proxy/internal/tunnel"
)

var Version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "epsilon-proxy",
		Short:   "Epsilon Secure Proxy — keep your data encrypted at the source",
		Version: Version,
	}

	rootCmd.AddCommand(registerCmd())
	rootCmd.AddCommand(startCmd())
	rootCmd.AddCommand(devCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(unregisterCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func registerCmd() *cobra.Command {
	var token string
	var apiURL string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register this proxy with the Epsilon platform",
		Long: `Register this proxy with the Epsilon platform.

Database credentials are entered interactively (never passed as CLI flags
to avoid leaking them in shell history or process listings).

Alternatively, set the EPSILON_DB_URL environment variable.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if token == "" {
				return fmt.Errorf("--token is required")
			}
			if apiURL == "" {
				return fmt.Errorf("--api-url is required")
			}

			reg := registration.New(apiURL)
			return reg.Register(cmd.Context(), token)
		},
	}

	cmd.Flags().StringVar(&token, "token", "", "Registration token from Epsilon platform")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Epsilon platform API URL")

	return cmd
}

func startCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the proxy server and tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Set up signal-aware context for graceful shutdown
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Start tunnel
			tunnelMgr := tunnel.New(cfg.Rathole)
			if err := tunnelMgr.Start(ctx); err != nil {
				return fmt.Errorf("failed to start tunnel: %w", err)
			}
			defer tunnelMgr.Stop()

			// Create DB client for heartbeat health checks
			dbClient := db.New(cfg.Database)

			// Start heartbeat goroutine (30s interval)
			hb := heartbeat.New(cfg, dbClient, Version)
			hb.Start(ctx)
			defer hb.Stop()

			// Start HTTP server
			srv := server.New(cfg)
			fmt.Printf("Proxy running. Tunnel connected. Listening on %s\n", cfg.Server.ListenAddr)

			// Run server (blocks until context is cancelled)
			serverErr := srv.Run(ctx)

			// Graceful shutdown: notify platform we're going offline
			fmt.Println("\nShutting down...")
			offlineCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			hb.SendOffline(offlineCtx)

			return serverErr
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to config file (default: ~/.epsilon-proxy/config.yaml)")

	return cmd
}

func devCmd() *cobra.Command {
	var listenAddr string
	var dbURL string

	cmd := &cobra.Command{
		Use:   "dev",
		Short: "Start in dev mode (no tunnel, no attestation, no HMAC)",
		Long: `Start the proxy in development mode for local testing.

Skips rathole tunnel, attestation verification, and HMAC signature checks.
Connects directly to a local database. DO NOT use in production.

Requires EPSILON_DB_URL env var or --db-url flag (dev mode only).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbURL == "" {
				dbURL = os.Getenv("EPSILON_DB_URL")
			}
			if dbURL == "" {
				return fmt.Errorf("set EPSILON_DB_URL env var or use --db-url (safe in dev mode)")
			}

			cfg := &config.Config{
				ProxyID:     "dev-proxy",
				DatasetID:   "dev-dataset",
				PlatformURL: "http://localhost",
				ProxyToken:  "dev-token",
				DevMode:     true,
				Database: config.DatabaseConfig{
					URL:            dbURL,
					SSLMode:        "disable",
					MaxConnections: 5,
					QueryTimeoutS:  120,
				},
				Server: config.ServerConfig{
					ListenAddr: listenAddr,
				},
			}

			srv := server.New(cfg)
			fmt.Println("=== DEV MODE === (no tunnel, no attestation, no HMAC)")
			fmt.Printf("Listening on %s\n", cfg.Server.ListenAddr)
			fmt.Printf("Database:    %s\n", cfg.Database.Host())
			fmt.Println()
			return srv.Run(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&listenAddr, "listen", "127.0.0.1:8443", "Listen address")
	cmd.Flags().StringVar(&dbURL, "db-url", "", "Database URL (dev mode only, safe — no registration)")

	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check proxy status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load("")
			if err != nil {
				return fmt.Errorf("not configured: %w", err)
			}

			fmt.Printf("Proxy ID:    %s\n", cfg.ProxyID)
			fmt.Printf("Dataset ID:  %s\n", cfg.DatasetID)
			fmt.Printf("Platform:    %s\n", cfg.PlatformURL)
			fmt.Printf("Listen:      %s\n", cfg.Server.ListenAddr)
			fmt.Printf("DB Host:     %s\n", cfg.Database.Host())
			return nil
		},
	}
}

func unregisterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unregister",
		Short: "Unregister this proxy and remove local config",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Try to notify platform before removing config
			cfg, err := config.Load("")
			if err == nil && cfg.ProxyToken != "" {
				hb := heartbeat.New(cfg, nil, Version)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				hb.SendOffline(ctx)
			}
			return config.Remove()
		},
	}
}
