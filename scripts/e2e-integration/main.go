// E2E Integration Test: Tests the full proxy lifecycle against a running API.
//
// Prerequisites:
//   - API running at API_URL (default: http://localhost:3000)
//   - A project with connectionType=PROXY created in the platform
//   - An install token generated for that project
//
// Usage:
//
//	go run ./scripts/e2e-integration --api-url http://localhost:3000 --token ept_xxx
//
// Or test with a mock API server (built-in):
//
//	go run ./scripts/e2e-integration --mock
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	useMock := false
	apiURL := "http://localhost:3000"
	token := ""

	for i, arg := range os.Args[1:] {
		switch arg {
		case "--mock":
			useMock = true
		case "--api-url":
			if i+2 < len(os.Args) {
				apiURL = os.Args[i+2]
			}
		case "--token":
			if i+2 < len(os.Args) {
				token = os.Args[i+2]
			}
		}
	}

	if useMock {
		server := startMockAPI()
		defer server.Close()
		apiURL = server.URL
		token = "ept_mock_test_token_123"
		fmt.Println("=== Using mock API server ===")
	}

	if token == "" {
		log.Fatal("--token is required (or use --mock for mock API)")
	}

	fmt.Printf("API URL: %s\n", apiURL)
	fmt.Printf("Token:   %s\n\n", token[:10]+"...")

	// Step 1: Register
	fmt.Println("Step 1: Register proxy...")
	regResp, err := testRegister(apiURL, token)
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	fmt.Printf("  Proxy ID:       %s\n", regResp.ProxyID)
	fmt.Printf("  Proxy Token:    %s...%s\n", regResp.ProxyToken[:6], regResp.ProxyToken[len(regResp.ProxyToken)-4:])
	fmt.Printf("  Server Addr:    %s\n", regResp.ServerAddr)
	fmt.Printf("  Service Name:   %s\n", regResp.ServiceName)
	fmt.Printf("  Assigned Port:  %d\n", regResp.AssignedPort)
	fmt.Println("  PASS")

	// Step 2: Heartbeat
	fmt.Println("\nStep 2: Send heartbeat...")
	if err := testHeartbeat(apiURL, regResp.ProxyToken); err != nil {
		log.Fatalf("Heartbeat failed: %v", err)
	}
	fmt.Println("  PASS")

	// Step 3: Send 3 heartbeats at 1s interval
	fmt.Println("\nStep 3: Send 3 rapid heartbeats...")
	for i := 0; i < 3; i++ {
		if err := testHeartbeat(apiURL, regResp.ProxyToken); err != nil {
			log.Fatalf("Heartbeat %d failed: %v", i+1, err)
		}
		fmt.Printf("  Heartbeat %d sent\n", i+1)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("  PASS")

	// Step 4: Send offline
	fmt.Println("\nStep 4: Send offline notification...")
	if err := testOffline(apiURL, regResp.ProxyToken); err != nil {
		log.Fatalf("Offline notification failed: %v", err)
	}
	fmt.Println("  PASS")

	fmt.Println("\n=== ALL E2E INTEGRATION TESTS PASSED ===")
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

func testRegister(apiURL, installToken string) (*registerResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"installToken": installToken,
		"version":      "test-0.1.0",
		"dbType":       "postgres",
	})

	resp, err := http.Post(apiURL+"/proxy/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST /proxy/register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}

	var result registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	if result.ProxyID == "" || result.ProxyToken == "" {
		return nil, fmt.Errorf("missing proxyId or proxyToken in response")
	}

	return &result, nil
}

func testHeartbeat(apiURL, proxyToken string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"proxyToken":        proxyToken,
		"version":           "test-0.1.0",
		"databaseReachable": true,
		"tunnelConnected":   true,
		"uptimeSeconds":     42,
	})

	resp, err := http.Post(apiURL+"/proxy/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST /proxy/heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

func testOffline(apiURL, proxyToken string) error {
	body, _ := json.Marshal(map[string]string{
		"proxyToken": proxyToken,
	})

	resp, err := http.Post(apiURL+"/proxy/offline", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST /proxy/offline: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

// startMockAPI creates a simple mock of the platform API for testing without a real backend.
func startMockAPI() *httptest.Server {
	var heartbeatCount atomic.Int32

	mux := http.NewServeMux()

	mux.HandleFunc("POST /proxy/register", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)

		if body["installToken"] == "" {
			http.Error(w, `{"message":"Missing installToken"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registerResponse{
			ProxyID:        "px-test-001",
			ProxyToken:     "pt_mock_token_" + fmt.Sprintf("%d", time.Now().UnixNano()),
			RatholeToken:   "rt_mock_token",
			NoisePublicKey: "mock_noise_key_base64",
			ServerAddr:     "127.0.0.1:7000",
			ServiceName:    "proxy-px-test-001",
			AssignedPort:   10000,
		})
	})

	mux.HandleFunc("POST /proxy/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		if body["proxyToken"] == nil || body["proxyToken"] == "" {
			http.Error(w, `{"message":"Missing proxyToken"}`, http.StatusUnauthorized)
			return
		}

		heartbeatCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /proxy/offline", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)

		if body["proxyToken"] == "" {
			http.Error(w, `{"message":"Missing proxyToken"}`, http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	return httptest.NewServer(mux)
}
