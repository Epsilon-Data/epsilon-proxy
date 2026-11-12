package crypto

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// ErrNoExpectedPCR0 is returned when no expected enclave image is configured.
var ErrNoExpectedPCR0 = errors.New("no expected PCR0 is configured: no enclave image is accepted")

// AttestationResult holds the verified attestation data.
type AttestationResult struct {
	PublicKey string // PEM-encoded RSA public key from user_data
	PCR0      []byte // 48 bytes SHA-384 enclave image hash
	ModuleID  string
	Timestamp uint64
}

// attestationPayload is the CBOR structure inside the COSE_Sign1 payload.
type attestationPayload struct {
	ModuleID    string            `cbor:"module_id"`
	Timestamp   uint64            `cbor:"timestamp"`
	Digest      string            `cbor:"digest"`
	PCRs        map[uint][]byte   `cbor:"pcrs"`
	Certificate []byte            `cbor:"certificate"`
	CABundle    [][]byte          `cbor:"cabundle"`
	UserData    []byte            `cbor:"user_data"`
	Nonce       []byte            `cbor:"nonce"`
	PublicKey   []byte            `cbor:"public_key"`
}

// userData is the JSON structure embedded in the attestation user_data field.
type userData struct {
	PublicKey string `json:"public_key"`
	SessionID string `json:"session_id"`
}

// VerifyAttestation verifies an AWS Nitro Enclave attestation document.
// It validates the certificate chain, COSE signature, PCR0, and extracts the public key.
func VerifyAttestation(attestationB64 string, expectedPCR0Hex string) (*AttestationResult, error) {
	if expectedPCR0Hex == "" {
		return nil, ErrNoExpectedPCR0
	}

	// 1. Base64 decode
	raw, err := base64.StdEncoding.DecodeString(attestationB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode attestation: %w", err)
	}

	// 2. Parse COSE_Sign1 (AWS Nitro NSM returns untagged COSE_Sign1)
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(raw); err != nil {
		// Nitro attestation docs are untagged COSE_Sign1 (CBOR array, not tag 18).
		// Wrap with CBOR tag 18 and retry.
		tagged := append([]byte{0xd2}, raw...)
		if err2 := msg.UnmarshalCBOR(tagged); err2 != nil {
			return nil, fmt.Errorf("unmarshal COSE_Sign1: %w (also tried tagged: %v)", err, err2)
		}
	}

	// 3. Parse attestation payload from COSE payload
	var payload attestationPayload
	if err := cbor.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal attestation payload: %w", err)
	}

	// 4. Build certificate chain
	leafCert, err := x509.ParseCertificate(payload.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, cabytes := range payload.CABundle {
		cert, err := x509.ParseCertificate(cabytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA bundle certificate: %w", err)
		}
		intermediates.AddCert(cert)
	}

	// 5. Verify chain against AWS Nitro root cert
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(awsNitroRootCert)) {
		return nil, fmt.Errorf("failed to parse AWS Nitro root cert")
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// 6. Verify COSE_Sign1 signature
	verifier, err := cose.NewVerifier(cose.AlgorithmES384, leafCert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("create COSE verifier: %w", err)
	}

	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("COSE signature verification failed: %w", err)
	}

	// 7. Verify PCR0
	pcr0, ok := payload.PCRs[0]
	if !ok {
		return nil, fmt.Errorf("PCR0 not found in attestation")
	}

	if err := matchPCR0(pcr0, expectedPCR0Hex); err != nil {
		return nil, err
	}

	// 8. Extract public key from user_data
	var ud userData
	if err := json.Unmarshal(payload.UserData, &ud); err != nil {
		return nil, fmt.Errorf("unmarshal user_data: %w", err)
	}

	if ud.PublicKey == "" {
		return nil, fmt.Errorf("no public_key in attestation user_data")
	}

	return &AttestationResult{
		PublicKey: ud.PublicKey,
		PCR0:     pcr0,
		ModuleID: payload.ModuleID,
		Timestamp: payload.Timestamp,
	}, nil
}

// matchPCR0 compares the attested PCR0 with the expected one. An empty expected
// value matches nothing: without it any genuine enclave image would be accepted.
func matchPCR0(pcr0 []byte, expectedPCR0Hex string) error {
	if expectedPCR0Hex == "" {
		return ErrNoExpectedPCR0
	}
	expectedPCR0, err := hex.DecodeString(expectedPCR0Hex)
	if err != nil {
		return fmt.Errorf("decode expected PCR0: %w", err)
	}
	if len(pcr0) != len(expectedPCR0) {
		return fmt.Errorf("PCR0 length mismatch: got %d, expected %d", len(pcr0), len(expectedPCR0))
	}
	if subtle.ConstantTimeCompare(pcr0, expectedPCR0) != 1 {
		return fmt.Errorf("PCR0 mismatch: attestation does not match expected enclave image")
	}
	return nil
}

// AWS Nitro Enclaves Root Certificate (Root G1)
// Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
const awsNitroRootCert = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`
