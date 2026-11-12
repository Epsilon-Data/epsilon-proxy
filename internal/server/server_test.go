package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
	"github.com/Epsilon-Data/epsilon-proxy/internal/crypto"
	"github.com/Epsilon-Data/epsilon-proxy/internal/db"
	"github.com/Epsilon-Data/epsilon-proxy/internal/releaselog"
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
		cfg: &config.Config{
			ProxyToken:  "test-token",
			Attestation: config.AttestationConfig{ExpectedPCR0: testPCR0Hex},
		},
		verifyAttestation: func(string, string) (*crypto.AttestationResult, error) {
			return &crypto.AttestationResult{
				PublicKey: "pubkey",
				PCR0:      testPCR0,
				ModuleID:  "i-0abc-enc0123",
				Timestamp: uint64(signedAt.UnixMilli()),
			}, nil
		},
		freshness: crypto.NewFreshnessGuard(5*time.Minute, time.Now),
		releases:  releaselog.New(filepath.Join(os.TempDir(), "epsilon-proxy-test-unused-releases.log")),
	}
}

var (
	testPCR0    = bytes.Repeat([]byte{0xab}, 48)
	testPCR0Hex = strings.Repeat("ab", 48)
)

const releasedCSV = "age,sex\n42,F\n57,M\n"

// releasingServer passes the attestation checks for a document bound to publicKeyPEM, answers
// every query with releasedCSV and writes its release log under a test directory.
func releasingServer(t *testing.T, publicKeyPEM string) (*Server, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "releases.log")
	s := serverWithVerifiedDocument(time.Now())
	s.verifyAttestation = func(string, string) (*crypto.AttestationResult, error) {
		return &crypto.AttestationResult{
			PublicKey: publicKeyPEM,
			PCR0:      testPCR0,
			ModuleID:  "i-0abc-enc0123",
			Timestamp: uint64(time.Now().UnixMilli()),
		}, nil
	}
	s.runQuery = func(context.Context, string) (*db.QueryResult, error) {
		return &db.QueryResult{CSV: []byte(releasedCSV), RowCount: 2, ColCount: 2}, nil
	}
	s.releases = releaselog.New(logPath)
	s.cfg.Database.QueryTimeoutS = 60
	return s, logPath
}

func testPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func postQueryWithKey(t *testing.T, s *Server, publicKeyPEM, sql string) (int, QueryResponse) {
	t.Helper()
	req := QueryRequest{
		RequestID:        "req-7",
		SessionID:        "session-7",
		SQLQuery:         sql,
		EnclavePublicKey: publicKeyPEM,
		AttestationDoc:   "doc",
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
	return w.Code, resp
}

func releaseLogLines(t *testing.T, path string) []releaselog.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var entries []releaselog.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry releaselog.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestNoExpectedPCR0ServesNothing(t *testing.T) {
	// The attestation check would pass: only the missing expected PCR0 stops the request
	s := serverWithVerifiedDocument(time.Now())
	s.cfg.Attestation.ExpectedPCR0 = ""

	code, resp := postQueryWithKey(t, s, "pubkey", "SELECT 1")

	if code != http.StatusServiceUnavailable || resp.Error != "EXPECTED_PCR0_NOT_CONFIGURED" || resp.EncryptedCSV != "" {
		t.Fatalf("status = %d, response = %+v, want 503 EXPECTED_PCR0_NOT_CONFIGURED and no data", code, resp)
	}
}

func TestNoReleaseLogServesNothing(t *testing.T) {
	s := serverWithVerifiedDocument(time.Now())
	s.releases = nil

	code, resp := postQueryWithKey(t, s, "pubkey", "SELECT 1")

	if code != http.StatusServiceUnavailable || resp.Error != "RELEASE_LOG_NOT_CONFIGURED" || resp.EncryptedCSV != "" {
		t.Fatalf("status = %d, response = %+v, want 503 RELEASE_LOG_NOT_CONFIGURED and no data", code, resp)
	}
}

func TestReleaseIsLoggedWithTheExtractDigest(t *testing.T) {
	publicKeyPEM := testPublicKeyPEM(t)
	s, logPath := releasingServer(t, publicKeyPEM)
	query := "SELECT age, sex\nFROM patients"

	code, resp := postQueryWithKey(t, s, publicKeyPEM, query)

	if code != http.StatusOK || !resp.Success || resp.EncryptedCSV == "" {
		t.Fatalf("status = %d, response = %+v, want a released extract", code, resp)
	}
	entries := releaseLogLines(t, logPath)
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(entries))
	}
	digest := sha256.Sum256([]byte(releasedCSV))
	want := releaselog.Entry{
		Time:          entries[0].Time,
		RequestID:     "req-7",
		SessionID:     "session-7",
		Attested:      true,
		PCR0:          testPCR0Hex,
		ModuleID:      "i-0abc-enc0123",
		SQLQuery:      query,
		RowCount:      2,
		ColumnCount:   2,
		ExtractSHA256: hex.EncodeToString(digest[:]),
	}
	if entries[0] != want {
		t.Fatalf("entry = %+v, want %+v", entries[0], want)
	}
	if _, err := time.Parse(time.RFC3339Nano, entries[0].Time); err != nil {
		t.Fatalf("time %q: %v", entries[0].Time, err)
	}
}

func TestNothingIsReleasedWhenTheLogCannotBeWritten(t *testing.T) {
	publicKeyPEM := testPublicKeyPEM(t)
	s, _ := releasingServer(t, publicKeyPEM)
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s.releases = releaselog.New(filepath.Join(blocker, "releases.log"))

	code, resp := postQueryWithKey(t, s, publicKeyPEM, "SELECT age FROM patients")

	if code != http.StatusInternalServerError || resp.Error != "RELEASE_LOG_FAILED" || resp.EncryptedCSV != "" {
		t.Fatalf("status = %d, response = %+v, want 500 RELEASE_LOG_FAILED and no data", code, resp)
	}
}

func TestRefusedRequestsAreNotLoggedAsReleases(t *testing.T) {
	publicKeyPEM := testPublicKeyPEM(t)
	s, logPath := releasingServer(t, publicKeyPEM)

	if _, resp := postQueryWithKey(t, s, publicKeyPEM, blockedQuery); resp.Error != "QUERY_BLOCKED" {
		t.Fatalf("response = %+v, want QUERY_BLOCKED", resp)
	}
	s.runQuery = func(context.Context, string) (*db.QueryResult, error) {
		return nil, errors.New("relation does not exist")
	}
	s.freshness = crypto.NewFreshnessGuard(5*time.Minute, time.Now)
	if _, resp := postQueryWithKey(t, s, publicKeyPEM, "SELECT age FROM missing"); resp.Error != "QUERY_FAILED" {
		t.Fatalf("response = %+v, want QUERY_FAILED", resp)
	}

	if entries := releaseLogLines(t, logPath); len(entries) != 0 {
		t.Fatalf("log entries = %+v, want none", entries)
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
