// e2e-test simulates what the coordinator does:
// 1. Generate an RSA keypair (simulating the enclave)
// 2. Send a query request to the proxy with the public key
// 3. Receive encrypted CSV
// 4. Decrypt it with the private key (simulating enclave decryption)
// 5. Print the decrypted CSV
//
// Usage:
//   Start proxy:  epsilon-proxy dev --db-url "postgres://user:pass@localhost:5432/mydb"
//   Run test:     go run ./scripts/e2e-test
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

const proxyURL = "http://127.0.0.1:8443"

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
		RowCount          int   `json:"row_count"`
		ColumnCount       int   `json:"column_count"`
		EncryptedSizeBytes int  `json:"encrypted_size_bytes"`
		QueryDurationMs   int64 `json:"query_duration_ms"`
		EncryptDurationMs int64 `json:"encryption_duration_ms"`
	} `json:"metadata"`
}

func main() {
	sqlQuery := "SELECT tablename FROM pg_tables WHERE schemaname = 'public' LIMIT 10"
	if len(os.Args) > 1 {
		sqlQuery = os.Args[1]
	}

	fmt.Println("=== Epsilon-Proxy E2E Test ===")
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

	// Step 2: Check proxy health
	fmt.Print("2. Checking proxy health... ")
	resp, err := http.Get(proxyURL + "/health")
	if err != nil {
		fatal("health check failed: %v\n   Is the proxy running? Start it with: epsilon-proxy dev --db-url <your-db-url>", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		fatal("health check returned %d", resp.StatusCode)
	}
	fmt.Println("OK")

	// Step 3: Send query to proxy
	fmt.Printf("3. Sending query: %s\n", sqlQuery)
	fmt.Print("   Waiting for response... ")

	reqBody := queryRequest{
		RequestID:        fmt.Sprintf("test-%d", time.Now().UnixNano()),
		SessionID:        "test-session-001",
		SQLQuery:         sqlQuery,
		EnclavePublicKey: pubPEM,
		Timestamp:        time.Now().Unix(),
	}

	body, _ := json.Marshal(reqBody)
	resp, err = http.Post(proxyURL+"/query", "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("query failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var qResp queryResponse
	if err := json.Unmarshal(respBody, &qResp); err != nil {
		fatal("parse response: %v\nRaw: %s", err, string(respBody))
	}

	if !qResp.Success {
		fatal("query failed: %s — %s", qResp.Error, qResp.Message)
	}
	fmt.Println("OK")

	fmt.Printf("   Rows: %d | Columns: %d | Encrypted size: %d bytes\n",
		qResp.Metadata.RowCount, qResp.Metadata.ColumnCount, qResp.Metadata.EncryptedSizeBytes)
	fmt.Printf("   Query: %dms | Encryption: %dms\n",
		qResp.Metadata.QueryDurationMs, qResp.Metadata.EncryptDurationMs)

	// Step 4: Decrypt (simulating enclave decryption)
	fmt.Print("4. Decrypting with private key (simulating enclave)... ")
	decrypted, err := decryptHybrid(qResp.EncryptedCSV, privKey)
	if err != nil {
		fatal("decrypt: %v", err)
	}
	fmt.Println("OK")

	// Step 5: Print result
	fmt.Println()
	fmt.Println("=== Decrypted CSV ===")
	fmt.Println(string(decrypted))
	fmt.Println("=== E2E Test PASSED ===")
}

func decryptHybrid(encryptedB64 string, privKey *rsa.PrivateKey) ([]byte, error) {
	combined, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}

	keySize := privKey.Size() // 256 for RSA-2048
	if len(combined) < keySize+16 {
		return nil, fmt.Errorf("data too short: %d bytes", len(combined))
	}

	encKey := combined[:keySize]
	iv := combined[keySize : keySize+16]
	ciphertext := combined[keySize+16:]

	// RSA-OAEP decrypt
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA: %w", err)
	}

	// AES-256-CBC decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES: %w", err)
	}

	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)

	// Remove PKCS7 padding
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
