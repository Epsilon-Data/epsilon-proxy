package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
	"github.com/Epsilon-Data/epsilon-proxy/internal/db"
)

const (
	DefaultInterval = 30 * time.Second
	requestTimeout  = 10 * time.Second
)

type heartbeatRequest struct {
	ProxyToken        string `json:"proxyToken"`
	Version           string `json:"version,omitempty"`
	DatabaseReachable bool   `json:"databaseReachable"`
	TunnelConnected   bool   `json:"tunnelConnected"`
	UptimeSeconds     int64  `json:"uptimeSeconds,omitempty"`
}

type offlineRequest struct {
	ProxyToken string `json:"proxyToken"`
}

// Service sends periodic heartbeats to the platform API.
type Service struct {
	cfg        *config.Config
	httpClient *http.Client
	dbClient   *db.Client
	version    string
	startedAt  time.Time
	cancel     context.CancelFunc
	done       chan struct{}
}

func New(cfg *config.Config, dbClient *db.Client, version string) *Service {
	return &Service{
		cfg:       cfg,
		version:   version,
		dbClient:  dbClient,
		startedAt: time.Now(),
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
		done: make(chan struct{}),
	}
}

// Start begins sending heartbeats every 30 seconds.
func (s *Service) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	go func() {
		defer close(s.done)

		// Send first heartbeat immediately
		s.sendHeartbeat(ctx)

		ticker := time.NewTicker(DefaultInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sendHeartbeat(ctx)
			}
		}
	}()

	log.Printf("[heartbeat] Started (every %s)", DefaultInterval)
}

// Stop cancels the heartbeat loop.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	<-s.done
}

// SendOffline notifies the platform that this proxy is going offline.
func (s *Service) SendOffline(ctx context.Context) {
	body := offlineRequest{
		ProxyToken: s.cfg.ProxyToken,
	}

	data, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/proxy/offline", s.cfg.PlatformURL)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		log.Printf("[heartbeat] Failed to create offline request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("[heartbeat] Failed to send offline notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		log.Printf("[heartbeat] Offline notification sent")
	} else {
		log.Printf("[heartbeat] Offline notification failed: status %d", resp.StatusCode)
	}
}

func (s *Service) sendHeartbeat(ctx context.Context) {
	dbReachable := false
	if s.dbClient != nil {
		if err := s.dbClient.Ping(ctx); err == nil {
			dbReachable = true
		}
	}

	body := heartbeatRequest{
		ProxyToken:        s.cfg.ProxyToken,
		Version:           s.version,
		DatabaseReachable: dbReachable,
		TunnelConnected:   true, // TODO: check rathole subprocess status
		UptimeSeconds:     int64(time.Since(s.startedAt).Seconds()),
	}

	data, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/proxy/heartbeat", s.cfg.PlatformURL)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		log.Printf("[heartbeat] Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("[heartbeat] Send failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		log.Printf("[heartbeat] Unexpected status: %d", resp.StatusCode)
	}
}
