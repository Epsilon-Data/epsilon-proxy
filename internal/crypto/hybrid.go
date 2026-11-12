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
	"fmt"
)

const (
	AESKeySize   = 32 // 256 bits
	GCMNonceSize = 12 // 96 bits, standard for AES-GCM
	GCMTagSize   = 16 // 128-bit authentication tag (appended by gcm.Seal)
)

// Encrypt performs RSA-2048-OAEP + AES-256-GCM authenticated hybrid encryption.
// Output format: base64(encrypted_aes_key || nonce || ciphertext‖tag)
//
// AES-GCM provides confidentiality AND integrity: the 16-byte authentication
// tag that gcm.Seal appends to the ciphertext lets the enclave detect any
// tampering (a modified payload fails tag verification on decrypt). A fresh
// random AES-256 key is generated per message, so the random 12-byte nonce is
// never reused under the same key.
//
// This MUST produce output the Python enclave's AES-GCM decryption can open.
func Encrypt(plaintext []byte, publicKeyPEM string) (string, error) {
	pubKey, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}

	// Generate a fresh random AES-256 key for this message
	aesKey := make([]byte, AESKeySize)
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("generate AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	// Generate a fresh random 96-bit nonce (unique under this one-time key)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Seal authenticates and encrypts; the 16-byte tag is appended to ciphertext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// RSA-OAEP encrypt the AES key (SHA-256 hash, SHA-256 MGF1)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("RSA encrypt AES key: %w", err)
	}

	// Combine: encrypted_key || nonce || ciphertext‖tag
	combined := make([]byte, 0, len(encryptedKey)+len(nonce)+len(ciphertext))
	combined = append(combined, encryptedKey...)
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)

	return base64.StdEncoding.EncodeToString(combined), nil
}

// ParsePublicKey parses an RSA public key from PEM format.
// Handles keys with or without PEM headers.
func ParsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	// Try to decode as PEM
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		// Try wrapping as PEM
		wrapped := "-----BEGIN PUBLIC KEY-----\n" + pemStr + "\n-----END PUBLIC KEY-----"
		block, _ = pem.Decode([]byte(wrapped))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}
