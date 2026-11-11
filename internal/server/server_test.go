package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
	"github.com/Epsilon-Data/epsilon-proxy/internal/crypto"
)

func TestQueryWithoutAttestationIsRefused(t *testing.T) {
	// No database client: a request that got past the attestation check would panic on the query
	s := &Server{cfg: &config.Config{ProxyToken: "test-token"}}

	req := QueryRequest{
		RequestID:        "req-1",
		SessionID:        "session-1",
		SQLQuery:         "SELECT 1",
		EnclavePublicKey: "pubkey",
		Timestamp:        time.Now().Unix(),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/query", bytes.NewReader(body))
	r.Header.Set("X-Signature", crypto.SignRequest("test-token", req.RequestID, req.SessionID, req.Timestamp))
	w := httptest.NewRecorder()

	s.handleQuery(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	var resp QueryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "ATTESTATION_REQUIRED" || resp.EncryptedCSV != "" {
		t.Fatalf("response = %+v, want ATTESTATION_REQUIRED and no data", resp)
	}
}

func postQuery(t *testing.T, s *Server, attestationDoc, sql string) QueryResponse {
	t.Helper()
	req := QueryRequest{
		RequestID:        "req-1",
		SessionID:        "session-1",
		SQLQuery:         sql,
		EnclavePublicKey: "pubkey",
		AttestationDoc:   attestationDoc,
		Timestamp:        time.Now().Unix(),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/query", bytes.NewReader(body))
	r.Header.Set("X-Signature", crypto.SignRequest("test-token", req.RequestID, req.SessionID, req.Timestamp))
	w := httptest.NewRecorder()

	s.handleQuery(w, r)

	var resp QueryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// serverWithVerifiedDocument returns a server whose attestation check passes for any document
// and reports signedAt as its signed time. It has no database client: a request that reached
// the query would panic, so the tests send a query that is blocked right after the checks.
func serverWithVerifiedDocument(signedAt time.Time) *Server {
	return &Server{
		cfg: &config.Config{ProxyToken: "test-token"},
		verifyAttestation: func(string, string) (*crypto.AttestationResult, error) {
			return &crypto.AttestationResult{
				PublicKey: "pubkey",
				PCR0:      make([]byte, 48),
				Timestamp: uint64(signedAt.UnixMilli()),
			}, nil
		},
		freshness: crypto.NewFreshnessGuard(5*time.Minute, time.Now),
	}
}

const blockedQuery = "DROP TABLE patients"

func TestReplayedAttestationIsRefused(t *testing.T) {
	s := serverWithVerifiedDocument(time.Now())

	if resp := postQuery(t, s, "doc", blockedQuery); resp.Error != "QUERY_BLOCKED" {
		t.Fatalf("first use: response = %+v, want to pass the attestation checks", resp)
	}
	resp := postQuery(t, s, "doc", "SELECT 1")
	if resp.Error != "ATTESTATION_REPLAYED" || resp.EncryptedCSV != "" {
		t.Fatalf("second use: response = %+v, want ATTESTATION_REPLAYED and no data", resp)
	}
}

func TestStaleAttestationIsRefused(t *testing.T) {
	s := serverWithVerifiedDocument(time.Now().Add(-6 * time.Minute))

	resp := postQuery(t, s, "doc", "SELECT 1")
	if resp.Error != "ATTESTATION_STALE" || resp.EncryptedCSV != "" {
		t.Fatalf("response = %+v, want ATTESTATION_STALE and no data", resp)
	}
}
