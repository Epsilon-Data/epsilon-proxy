// e2e-test-tunnel runs the same test as e2e-test but through the rathole tunnel.
// This simulates the PRODUCTION flow where the coordinator reaches the proxy
// via the rathole relay server — not directly.
//
// Setup:
//   1. rathole server on :7000 (simulates EC2 relay)
//   2. epsilon-proxy on :8443 (data owner's machine)
//   3. rathole client tunnels :8443 → :17001 via :7000
//   4. This test hits :17001 (the tunnel endpoint)
//
// The coordinator in production would hit localhost:17001 (rathole's bind_addr).
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// This is the tunnel endpoint — what the coordinator would use
const proxyURL = "http://127.0.0.1:17001"

type queryRequest struct {
	RequestID        string `json:"request_id"`
	SessionID        string `json:"session_id"`
	SQLQuery         string `json:"sql_query"`
	EnclavePublicKey string `json:"enclave_public_key"`
	AttestationDoc   string `json:"attestation_document"`
	Timestamp        int64  `json:"timestamp"`
}

type queryResponse struct {
	Success      bool   `json:"success"`
	EncryptedCSV string `json:"encrypted_csv"`
	Error        string `json:"error"`
	Message      string `json:"message"`
	Metadata     *struct {
		RowCount           int   `json:"row_count"`
		ColumnCount        int   `json:"column_count"`
		EncryptedSizeBytes int   `json:"encrypted_size_bytes"`
		QueryDurationMs    int64 `json:"query_duration_ms"`
		EncryptDurationMs  int64 `json:"encryption_duration_ms"`
	} `json:"metadata"`
}

func main() {
	sqlQuery := "SELECT * FROM patient LIMIT 5"
	if len(os.Args) > 1 {
		sqlQuery = os.Args[1]
	}

	fmt.Println("=== Epsilon-Proxy E2E Test (VIA RATHOLE TUNNEL) ===")
	fmt.Printf("    Tunnel endpoint: %s\n", proxyURL)
	fmt.Println()

	// Step 1: Generate RSA keypair (simulating enclave)
	fmt.Print("1. Generating RSA-2048 keypair (simulating enclave)... ")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal("generate key: %v", err)
	}

	pubDER, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	fmt.Println("OK")

	// Step 2: Health check via tunnel
	fmt.Print("2. Health check via tunnel... ")
	resp, err := http.Get(proxyURL + "/health")
	if err != nil {
		fatal("tunnel unreachable: %v", err)
	}
	resp.Body.Close()
	fmt.Println("OK")

	// Step 3: Send query via tunnel
	fmt.Printf("3. Sending query via tunnel: %s\n", sqlQuery)
	fmt.Print("   Waiting for response... ")

	reqBody := queryRequest{
		RequestID:        fmt.Sprintf("tunnel-test-%d", time.Now().UnixNano()),
		SessionID:        "test-session-tunnel",
		SQLQuery:         sqlQuery,
		EnclavePublicKey: pubPEM,
		Timestamp:        time.Now().Unix(),
	}

	body, _ := json.Marshal(reqBody)
	resp, err = http.Post(proxyURL+"/query", "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("query via tunnel failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var qResp queryResponse
	if err := json.Unmarshal(respBody, &qResp); err != nil {
		fatal("parse response: %v", err)
	}

	if !qResp.Success {
		fatal("query failed: %s — %s", qResp.Error, qResp.Message)
	}
	fmt.Println("OK")

	fmt.Printf("   Rows: %d | Columns: %d | Encrypted size: %d bytes\n",
		qResp.Metadata.RowCount, qResp.Metadata.ColumnCount, qResp.Metadata.EncryptedSizeBytes)
	fmt.Printf("   Query: %dms | Encryption: %dms\n",
		qResp.Metadata.QueryDurationMs, qResp.Metadata.EncryptDurationMs)

	// Step 4: Decrypt
	fmt.Print("4. Decrypting with private key (simulating enclave)... ")
	decrypted, err := decryptHybrid(qResp.EncryptedCSV, privKey)
	if err != nil {
		fatal("decrypt: %v", err)
	}
	fmt.Println("OK")

	fmt.Println()
	fmt.Println("=== Decrypted CSV ===")
	fmt.Println(string(decrypted))

	fmt.Println("=== TUNNEL E2E Test PASSED ===")
	fmt.Println()
	fmt.Println("What just happened:")
	fmt.Println("  Test (coordinator) → :17001 (rathole server) → tunnel → :8443 (proxy) → :5433 (DB)")
	fmt.Println("  Proxy encrypted CSV with enclave's public key")
	fmt.Println("  Test (enclave) decrypted with private key")
	fmt.Println("  Coordinator/rathole only saw ciphertext!")
}

func decryptHybrid(encryptedB64 string, privKey *rsa.PrivateKey) ([]byte, error) {
	combined, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}

	keySize := privKey.Size()
	if len(combined) < keySize+16 {
		return nil, fmt.Errorf("data too short: %d bytes", len(combined))
	}

	encKey := combined[:keySize]
	iv := combined[keySize : keySize+16]
	ciphertext := combined[keySize+16:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES: %w", err)
	}

	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)

	padLen := int(padded[len(padded)-1])
	if padLen > 16 || padLen == 0 {
		return nil, fmt.Errorf("invalid padding: %d", padLen)
	}

	return padded[:len(padded)-padLen], nil
}

func fatal(format string, args ...any) {
	fmt.Printf("FAILED\n   "+format+"\n", args...)
	os.Exit(1)
}
