package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
	"github.com/Epsilon-Data/epsilon-proxy/internal/crawler"
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

type heartbeatResponse struct {
	Action string `json:"action,omitempty"`
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
	crawling  sync.Mutex
	beatCount int
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

	log.Printf("[heartbeat] Started (every %s) → %s", DefaultInterval, s.cfg.PlatformURL)
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
	var dbErr error
	if s.dbClient != nil {
		if err := s.dbClient.Ping(ctx); err == nil {
			dbReachable = true
		} else {
			dbErr = err
		}
	}

	// Log DB unreachable on first heartbeat and periodically (every 5 min = every 10th beat)
	s.beatCount++
	if !dbReachable && (s.beatCount == 1 || s.beatCount%10 == 0) {
		if dbErr != nil {
			log.Printf("[heartbeat] WARNING: Database unreachable: %v", dbErr)
		} else {
			log.Printf("[heartbeat] WARNING: No database client configured")
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

	if resp.StatusCode == http.StatusUnauthorized {
		log.Println("[heartbeat] Proxy was unregistered from the platform.")
		log.Println("[heartbeat] Cleaning up local config and shutting down...")
		config.Remove()
		if s.cancel != nil {
			s.cancel()
		}
		return
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[heartbeat] Unexpected status %d: %s", resp.StatusCode, string(respBody))
		return
	}

	// Parse response for action commands
	respBody, err := io.ReadAll(resp.Body)
	if err != nil || len(respBody) == 0 {
		return
	}

	var hbResp heartbeatResponse
	if err := json.Unmarshal(respBody, &hbResp); err != nil {
		return
	}

	if hbResp.Action == "crawl" {
		s.handleCrawlAction(ctx)
	}
}

func (s *Service) handleCrawlAction(ctx context.Context) {
	// Prevent concurrent crawls
	if !s.crawling.TryLock() {
		return
	}

	go func() {
		defer s.crawling.Unlock()
		log.Println("[heartbeat] Received crawl action from platform")

		if err := crawler.Run(ctx, s.cfg); err != nil {
			log.Printf("[heartbeat] Crawl failed: %v", err)
			return
		}

		log.Println("[heartbeat] Crawl completed and metadata uploaded")
	}()
}
