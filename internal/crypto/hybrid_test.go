package crypto

import (
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

// decryptHybrid mimics the Python enclave's decryption to verify compatibility.
func decryptHybrid(t *testing.T, encrypted string, privKey *rsa.PrivateKey) []byte {
	t.Helper()

	combined, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	keySize := privKey.Size() // 256 bytes for RSA-2048

	if len(combined) < keySize+IVSize {
		t.Fatalf("encrypted data too short: %d bytes", len(combined))
	}

	encryptedKey := combined[:keySize]
	iv := combined[keySize : keySize+IVSize]
	ciphertext := combined[keySize+IVSize:]

	// RSA-OAEP decrypt (SHA-256 hash, SHA-256 MGF1, no label)
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedKey, nil)
	if err != nil {
		t.Fatalf("RSA decrypt: %v", err)
	}

	if len(aesKey) != AESKeySize {
		t.Fatalf("AES key size: got %d, want %d", len(aesKey), AESKeySize)
	}

	// AES-256-CBC decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("AES cipher: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	padded := make([]byte, len(ciphertext))
	mode.CryptBlocks(padded, ciphertext)

	// Remove PKCS7 padding
	paddingLen := int(padded[len(padded)-1])
	if paddingLen > AESBlock || paddingLen == 0 {
		t.Fatalf("invalid PKCS7 padding: %d", paddingLen)
	}

	return padded[:len(padded)-paddingLen]
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
		{"exact_block_size", "0123456789abcdef"}, // 16 bytes = 1 AES block
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
		t.Error("two encryptions of same data produced identical ciphertext (random IV/key not working)")
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

	// Verify layout: [encrypted_key (256B)] [iv (16B)] [ciphertext (variable)]
	if len(combined) < keySize+IVSize+AESBlock {
		t.Fatalf("combined too short: %d bytes", len(combined))
	}

	ciphertextLen := len(combined) - keySize - IVSize

	// Ciphertext must be multiple of AES block size
	if ciphertextLen%AESBlock != 0 {
		t.Errorf("ciphertext length %d not multiple of block size %d", ciphertextLen, AESBlock)
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
