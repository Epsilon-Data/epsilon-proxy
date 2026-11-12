package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// generateTestKeypair creates an RSA-2048 keypair for testing.
func generateTestKeypair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return privKey, string(pubPEM)
}

// decryptHybrid mimics the Python enclave's AES-256-GCM decryption to verify
// wire-format compatibility. Layout: [encrypted_key][nonce][ciphertext‖tag].
func decryptHybrid(t *testing.T, encrypted string, privKey *rsa.PrivateKey) []byte {
	t.Helper()

	combined, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	keySize := privKey.Size() // 256 bytes for RSA-2048

	if len(combined) < keySize+GCMNonceSize+GCMTagSize {
		t.Fatalf("encrypted data too short: %d bytes", len(combined))
	}

	encryptedKey := combined[:keySize]
	nonce := combined[keySize : keySize+GCMNonceSize]
	ciphertext := combined[keySize+GCMNonceSize:] // includes 16-byte GCM tag

	// RSA-OAEP decrypt (SHA-256 hash, SHA-256 MGF1, no label)
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedKey, nil)
	if err != nil {
		t.Fatalf("RSA decrypt: %v", err)
	}

	if len(aesKey) != AESKeySize {
		t.Fatalf("AES key size: got %d, want %d", len(aesKey), AESKeySize)
	}

	// AES-256-GCM decrypt + tag verification
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new GCM: %v", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("GCM open (tag verification): %v", err)
	}

	return plaintext
}

func TestEncryptDecrypt(t *testing.T) {
	privKey, pubPEM := generateTestKeypair(t)

	tests := []struct {
		name      string
		plaintext string
	}{
		{"empty", ""},
		{"short", "hello world"},
		{"csv_header", "Age,BloodPressure,Name\n"},
		{"csv_data", "Age,Name\n25,Alice\n30,Bob\n35,Charlie\n"},
		{"unicode", "Schmerzbewertung,Patienten-ID\n7,P001\n"},
		{"sixteen_bytes", "0123456789abcdef"}, // 16 bytes; GCM needs no block alignment
		{"large", generateLargeCSV(10000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt([]byte(tt.plaintext), pubPEM)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			decrypted := decryptHybrid(t, encrypted, privKey)

			if string(decrypted) != tt.plaintext {
				t.Errorf("roundtrip failed:\n  got:  %q\n  want: %q", string(decrypted), tt.plaintext)
			}
		})
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	_, pubPEM := generateTestKeypair(t)
	plaintext := []byte("same data")

	enc1, _ := Encrypt(plaintext, pubPEM)
	enc2, _ := Encrypt(plaintext, pubPEM)

	if enc1 == enc2 {
		t.Error("two encryptions of same data produced identical ciphertext (random nonce/key not working)")
	}
}

func TestEncryptByteLayout(t *testing.T) {
	privKey, pubPEM := generateTestKeypair(t)
	plaintext := []byte("test data")

	encrypted, err := Encrypt(plaintext, pubPEM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	combined, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	keySize := privKey.Size() // 256

	// Verify layout: [encrypted_key (256B)] [nonce (12B)] [ciphertext‖tag]
	if len(combined) < keySize+GCMNonceSize+GCMTagSize {
		t.Fatalf("combined too short: %d bytes", len(combined))
	}

	// GCM ciphertext length == plaintext length; the appended tag adds 16 bytes.
	gotPayload := len(combined) - keySize - GCMNonceSize
	wantPayload := len(plaintext) + GCMTagSize
	if gotPayload != wantPayload {
		t.Errorf("ciphertext+tag length = %d, want plaintext(%d)+tag(%d) = %d",
			gotPayload, len(plaintext), GCMTagSize, wantPayload)
	}
}

// TestGCMTagRejectsTampering verifies the authentication tag: any modification
// to the ciphertext or to the tag itself must make decryption fail. This is the
// integrity property this encryption depends on.
func TestGCMTagRejectsTampering(t *testing.T) {
	privKey, pubPEM := generateTestKeypair(t)

	encrypted, err := Encrypt([]byte("sensitive patient row"), pubPEM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	combined, _ := base64.StdEncoding.DecodeString(encrypted)
	keySize := privKey.Size()

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, combined[:keySize], nil)
	if err != nil {
		t.Fatalf("RSA decrypt: %v", err)
	}
	nonce := combined[keySize : keySize+GCMNonceSize]
	ciphertext := combined[keySize+GCMNonceSize:]

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)

	// Sanity: untampered ciphertext opens cleanly
	if _, err := gcm.Open(nil, nonce, ciphertext, nil); err != nil {
		t.Fatalf("untampered open failed: %v", err)
	}

	// Flip a ciphertext byte -> tag must reject
	ct := bytes.Clone(ciphertext)
	ct[0] ^= 0x01
	if _, err := gcm.Open(nil, nonce, ct, nil); err == nil {
		t.Error("tampered ciphertext was accepted (authentication tag NOT enforced)")
	}

	// Flip a tag byte (last 16B) -> must reject
	ct2 := bytes.Clone(ciphertext)
	ct2[len(ct2)-1] ^= 0x01
	if _, err := gcm.Open(nil, nonce, ct2, nil); err == nil {
		t.Error("tampered authentication tag was accepted")
	}
}

func TestParsePublicKeyFormats(t *testing.T) {
	_, pubPEM := generateTestKeypair(t)

	// Standard PEM
	key, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("parse standard PEM: %v", err)
	}
	if key.Size() != 256 {
		t.Errorf("key size: got %d, want 256", key.Size())
	}

	// Raw base64 (no PEM headers)
	block, _ := pem.Decode([]byte(pubPEM))
	rawB64 := base64.StdEncoding.EncodeToString(block.Bytes)
	key2, err := ParsePublicKey(rawB64)
	if err != nil {
		t.Fatalf("parse raw base64: %v", err)
	}
	if key2.Size() != 256 {
		t.Errorf("key2 size: got %d, want 256", key2.Size())
	}
}

func generateLargeCSV(rows int) string {
	var b []byte
	b = append(b, "id,name,value\n"...)
	for i := 0; i < rows; i++ {
		b = append(b, []byte("12345,Alice Johnson,98.765\n")...)
	}
	return string(b)
}
