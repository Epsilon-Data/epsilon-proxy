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
	"fmt"
)

const (
	AESKeySize = 32 // 256 bits
	IVSize     = 16 // 128 bits
	AESBlock   = 16 // PKCS7 block size
)

// Encrypt performs RSA-2048-OAEP + AES-256-CBC hybrid encryption.
// Output format: base64(encrypted_aes_key || iv || ciphertext)
// This MUST produce output compatible with the Python enclave's decryption.
func Encrypt(plaintext []byte, publicKeyPEM string) (string, error) {
	pubKey, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}

	// Generate random AES-256 key
	aesKey := make([]byte, AESKeySize)
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("generate AES key: %w", err)
	}

	// Generate random IV
	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("generate IV: %w", err)
	}

	// PKCS7 pad the plaintext
	padded := pkcs7Pad(plaintext, AESBlock)

	// AES-256-CBC encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// RSA-OAEP encrypt the AES key (SHA-256 hash, SHA-256 MGF1)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("RSA encrypt AES key: %w", err)
	}

	// Combine: encrypted_key || iv || ciphertext
	combined := make([]byte, 0, len(encryptedKey)+len(iv)+len(ciphertext))
	combined = append(combined, encryptedKey...)
	combined = append(combined, iv...)
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

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}
