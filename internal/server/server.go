package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
	"github.com/Epsilon-Data/epsilon-proxy/internal/crypto"
	"github.com/Epsilon-Data/epsilon-proxy/internal/db"
)

type Server struct {
	cfg      *config.Config
	dbClient *db.Client
}

type QueryRequest struct {
	RequestID         string `json:"request_id"`
	SessionID         string `json:"session_id"`
	SQLQuery          string `json:"sql_query"`
	EnclavePublicKey  string `json:"enclave_public_key"`
	AttestationDoc    string `json:"attestation_document"`
	Timestamp         int64  `json:"timestamp"`
}

type QueryResponse struct {
	Success      bool            `json:"success"`
	EncryptedCSV string          `json:"encrypted_csv,omitempty"`
	Error        string          `json:"error,omitempty"`
	Message      string          `json:"message,omitempty"`
	Metadata     *QueryMetadata  `json:"metadata,omitempty"`
}

type QueryMetadata struct {
	RowCount           int   `json:"row_count"`
	ColumnCount        int   `json:"column_count"`
	EncryptedSizeBytes int   `json:"encrypted_size_bytes"`
	QueryDurationMs    int64 `json:"query_duration_ms"`
	EncryptDurationMs  int64 `json:"encryption_duration_ms"`
}

type HealthResponse struct {
	Status            string `json:"status"`
	Version           string `json:"version"`
	TunnelConnected   bool   `json:"tunnel_connected"`
	DatabaseReachable bool   `json:"database_reachable"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
}

var startTime = time.Now()

func New(cfg *config.Config) *Server {
	return &Server{
		cfg:      cfg,
		dbClient: db.New(cfg.Database),
	}
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /query", s.handleQuery)
	mux.HandleFunc("GET /health", s.handleHealth)

	srv := &http.Server{
		Addr:         s.cfg.Server.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown when parent context is cancelled
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	// 1. Parse request
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to parse request body")
		return
	}

	// 2. Verify HMAC signature (skip in dev mode)
	if !s.cfg.DevMode {
		signature := r.Header.Get("X-Signature")
		if err := crypto.VerifySignature(s.cfg.ProxyToken, req.RequestID, req.SessionID, req.Timestamp, signature); err != nil {
			writeError(w, http.StatusUnauthorized, "SIGNATURE_INVALID", err.Error())
			return
		}
	} else {
		log.Println("[DEV] Skipping HMAC verification")
	}

	// 3. Verify attestation document (skip in dev mode)
	publicKeyToUse := req.EnclavePublicKey

	if !s.cfg.DevMode && req.AttestationDoc != "" {
		result, err := crypto.VerifyAttestation(req.AttestationDoc, s.cfg.Attestation.ExpectedPCR0)
		if err != nil {
			writeError(w, http.StatusForbidden, "ATTESTATION_INVALID", err.Error())
			return
		}

		// Verify the public key in attestation matches the one in the request
		if result.PublicKey != req.EnclavePublicKey {
			writeError(w, http.StatusForbidden, "PCR_MISMATCH", "Public key in attestation does not match request")
			return
		}

		publicKeyToUse = result.PublicKey
	} else if s.cfg.DevMode {
		log.Println("[DEV] Skipping attestation verification")
	}

	// 4. Validate query
	if err := db.ValidateQuery(req.SQLQuery); err != nil {
		writeError(w, http.StatusBadRequest, "QUERY_BLOCKED", err.Error())
		return
	}

	// 5. Execute query
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Database.QueryTimeoutS)*time.Second)
	defer cancel()

	queryResult, err := s.dbClient.Query(ctx, req.SQLQuery)
	if err != nil {
		code := "QUERY_FAILED"
		if ctx.Err() != nil {
			code = "QUERY_TIMEOUT"
		}
		writeError(w, http.StatusInternalServerError, code, err.Error())
		return
	}

	// 6. Encrypt CSV with enclave's public key
	encryptStart := time.Now()
	encrypted, err := crypto.Encrypt(queryResult.CSV, publicKeyToUse)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ENCRYPTION_FAILED", err.Error())
		return
	}
	encryptDuration := time.Since(encryptStart)

	// 7. Return encrypted result
	resp := QueryResponse{
		Success:      true,
		EncryptedCSV: encrypted,
		Metadata: &QueryMetadata{
			RowCount:           queryResult.RowCount,
			ColumnCount:        queryResult.ColCount,
			EncryptedSizeBytes: len(encrypted),
			QueryDurationMs:    queryResult.Duration.Milliseconds(),
			EncryptDurationMs:  encryptDuration.Milliseconds(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	log.Printf("[QUERY] request_id=%s rows=%d cols=%d query_ms=%d encrypt_ms=%d size=%d",
		req.RequestID, queryResult.RowCount, queryResult.ColCount,
		queryResult.Duration.Milliseconds(), encryptDuration.Milliseconds(), len(encrypted))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	dbReachable := false
	if err := s.dbClient.Ping(r.Context()); err == nil {
		dbReachable = true
	}

	resp := HealthResponse{
		Status:            "healthy",
		Version:           s.cfg.Version,
		TunnelConnected:   true, // TODO: check rathole subprocess
		DatabaseReachable: dbReachable,
		UptimeSeconds:     int64(time.Since(startTime).Seconds()),
	}

	if !dbReachable {
		resp.Status = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(QueryResponse{
		Success: false,
		Error:   code,
		Message: message,
	})

	log.Printf("[ERROR] code=%s message=%s", code, message)
}
