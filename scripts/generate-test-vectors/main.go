// generate-test-vectors produces encrypted test data that can be verified
// by the Python enclave's decryption code. This is the critical cross-language
// compatibility test.
//
// Usage:
//
//	go run ./scripts/generate-test-vectors
//	python3 scripts/cross-language-test.py
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/Epsilon-Data/epsilon-proxy/internal/crypto"
)

type testVector struct {
	Name      string `json:"name"`
	Plaintext string `json:"plaintext"`
	Encrypted string `json:"encrypted"`
}

type output struct {
	PrivateKey  string       `json:"private_key"`
	PublicKey   string       `json:"public_key"`
	TestVectors []testVector `json:"test_vectors"`
}

func main() {
	// Generate keypair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	pubDER, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	plaintexts := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"short", "hello world"},
		{"csv", "Age,Name\n25,Alice\n30,Bob\n"},
		{"unicode", "Schmerzbewertung,Patienten-ID\n7,P001\n"},
		{"block_aligned", "0123456789abcdef"},
	}

	var vectors []testVector
	for _, pt := range plaintexts {
		encrypted, err := crypto.Encrypt([]byte(pt.data), string(pubPEM))
		if err != nil {
			fmt.Fprintf(os.Stderr, "encrypt %s: %v\n", pt.name, err)
			os.Exit(1)
		}

		vectors = append(vectors, testVector{
			Name:      pt.name,
			Plaintext: pt.data,
			Encrypted: encrypted,
		})
	}

	out := output{
		PrivateKey:  string(privPEM),
		PublicKey:   string(pubPEM),
		TestVectors: vectors,
	}

	data, _ := json.MarshalIndent(out, "", "  ")

	outPath := "scripts/test-vectors.json"
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %d test vectors → %s\n", len(vectors), outPath)
	fmt.Println("Run: python3 scripts/cross-language-test.py")
}
