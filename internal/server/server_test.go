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
