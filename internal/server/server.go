package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
	"github.com/Epsilon-Data/epsilon-proxy/internal/crypto"
	"github.com/Epsilon-Data/epsilon-proxy/internal/db"
	"github.com/Epsilon-Data/epsilon-proxy/internal/releaselog"
)

type Server struct {
	cfg      *config.Config
	dbClient *db.Client

	verifyAttestation func(attestationB64, expectedPCR0Hex string) (*crypto.AttestationResult, error)
	freshness         *crypto.FreshnessGuard
	runQuery          func(ctx context.Context, sqlQuery string) (*db.QueryResult, error)
	// releases is the custodian's log of data releases; nil only in dev mode without a path
	releases *releaselog.Log
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

	// Sub-stage timings for per-execution evaluation (Rule 2 decomposition).
	ParseDurationMs             int64 `json:"parse_duration_ms"`
	HMACVerifyDurationMs        int64 `json:"hmac_verify_duration_ms"`
	AttestationVerifyDurationMs int64 `json:"attestation_verify_duration_ms"`
	SQLValidateDurationMs       int64 `json:"sql_validate_duration_ms"`
	TotalDurationMs             int64 `json:"total_duration_ms"`
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
	dbClient := db.New(cfg.Database)
	s := &Server{
		cfg:               cfg,
		dbClient:          dbClient,
		verifyAttestation: crypto.VerifyAttestation,
		freshness:         crypto.NewFreshnessGuard(time.Duration(cfg.Attestation.MaxAgeS)*time.Second, time.Now),
		runQuery:          dbClient.Query,
	}
	if cfg.ReleaseLogPath != "" {
		s.releases = releaselog.New(cfg.ReleaseLogPath)
	}
	return s
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
	handlerStart := time.Now()

	// 1. Parse request
	parseStart := time.Now()
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to parse request body")
		return
	}
	parseDuration := time.Since(parseStart)

	// 2. Verify HMAC signature (skip in dev mode)
	hmacStart := time.Now()
	if !s.cfg.DevMode {
		signature := r.Header.Get("X-Signature")
		if err := crypto.VerifySignature(s.cfg.ProxyToken, req.RequestID, req.SessionID, req.Timestamp, signature); err != nil {
			writeError(w, http.StatusUnauthorized, "SIGNATURE_INVALID", err.Error())
			return
		}
	} else {
		log.Println("[DEV] Skipping HMAC verification")
	}
	hmacDuration := time.Since(hmacStart)

	// 3. Verify attestation document (skip in dev mode)
	attestStart := time.Now()
	publicKeyToUse := req.EnclavePublicKey
	release := releaselog.Entry{RequestID: req.RequestID, SessionID: req.SessionID, SQLQuery: req.SQLQuery}

	if !s.cfg.DevMode && req.AttestationDoc == "" {
		log.Println("[ATTESTATION] Refused: no attestation document provided")
		writeError(w, http.StatusForbidden, "ATTESTATION_REQUIRED", "An attestation document is required")
		return
	} else if !s.cfg.DevMode {
		// Without an expected PCR0 any genuine enclave image would pass: serve nothing
		if s.cfg.Attestation.ExpectedPCR0 == "" {
			writeError(w, http.StatusServiceUnavailable, "EXPECTED_PCR0_NOT_CONFIGURED", crypto.ErrNoExpectedPCR0.Error())
			return
		}
		if s.releases == nil {
			writeError(w, http.StatusServiceUnavailable, "RELEASE_LOG_NOT_CONFIGURED", "No release log is configured")
			return
		}

		result, err := s.verifyAttestation(req.AttestationDoc, s.cfg.Attestation.ExpectedPCR0)
		if err != nil {
			writeError(w, http.StatusForbidden, "ATTESTATION_INVALID", err.Error())
			return
		}

		// Verify the public key in attestation matches the one in the request
		if result.PublicKey != req.EnclavePublicKey {
			writeError(w, http.StatusForbidden, "PCR_MISMATCH", "Public key in attestation does not match request")
			return
		}

		// A document is accepted once, and only while its signed time is recent
		if err := s.freshness.Accept(req.AttestationDoc, result.Timestamp); err != nil {
			code := "ATTESTATION_STALE"
			if errors.Is(err, crypto.ErrAttestationReplayed) {
				code = "ATTESTATION_REPLAYED"
			}
			log.Printf("[ATTESTATION] Refused: %v", err)
			writeError(w, http.StatusForbidden, code, err.Error())
			return
		}

		publicKeyToUse = result.PublicKey
		release.Attested = true
		release.PCR0 = fmt.Sprintf("%x", result.PCR0)
		release.ModuleID = result.ModuleID
		log.Printf("[ATTESTATION] Verified: PCR0=%s... module=%s public_key_match=true",
			fmt.Sprintf("%x", result.PCR0)[:16], result.ModuleID)
	} else {
		log.Println("[DEV] Skipping attestation verification")
	}
	attestDuration := time.Since(attestStart)

	// 4. Validate query
	sqlValidateStart := time.Now()
	if err := db.ValidateQuery(req.SQLQuery); err != nil {
		writeError(w, http.StatusBadRequest, "QUERY_BLOCKED", err.Error())
		return
	}
	sqlValidateDuration := time.Since(sqlValidateStart)

	// 5. Execute query
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Database.QueryTimeoutS)*time.Second)
	defer cancel()

	queryResult, err := s.runQuery(ctx, req.SQLQuery)
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

	// 7. Record the release in the custodian's log. Nothing is returned unless it is on disk
	if s.releases != nil {
		release.RowCount = queryResult.RowCount
		release.ColumnCount = queryResult.ColCount
		release.ExtractSHA256 = releaselog.ExtractDigest(queryResult.CSV)
		if err := s.releases.Record(release); err != nil {
			writeError(w, http.StatusInternalServerError, "RELEASE_LOG_FAILED", err.Error())
			return
		}
	}

	totalDuration := time.Since(handlerStart)

	// 8. Return encrypted result
	resp := QueryResponse{
		Success:      true,
		EncryptedCSV: encrypted,
		Metadata: &QueryMetadata{
			RowCount:                    queryResult.RowCount,
			ColumnCount:                 queryResult.ColCount,
			EncryptedSizeBytes:          len(encrypted),
			QueryDurationMs:             queryResult.Duration.Milliseconds(),
			EncryptDurationMs:           encryptDuration.Milliseconds(),
			ParseDurationMs:             parseDuration.Milliseconds(),
			HMACVerifyDurationMs:        hmacDuration.Milliseconds(),
			AttestationVerifyDurationMs: attestDuration.Milliseconds(),
			SQLValidateDurationMs:       sqlValidateDuration.Milliseconds(),
			TotalDurationMs:             totalDuration.Milliseconds(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	log.Printf("[QUERY] request_id=%s rows=%d cols=%d parse_ms=%d hmac_ms=%d attest_ms=%d sql_ms=%d query_ms=%d encrypt_ms=%d total_ms=%d size=%d",
		req.RequestID, queryResult.RowCount, queryResult.ColCount,
		parseDuration.Milliseconds(), hmacDuration.Milliseconds(), attestDuration.Milliseconds(),
		sqlValidateDuration.Milliseconds(), queryResult.Duration.Milliseconds(),
		encryptDuration.Milliseconds(), totalDuration.Milliseconds(), len(encrypted))
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
