#!/usr/bin/env python3
"""
Cross-language encryption test.
Verifies that Go-encrypted data can be decrypted by the Python enclave.

Usage:
  1. Run the Go test vector generator: go run ./scripts/generate-test-vectors
  2. Run this script: python3 scripts/cross-language-test.py

This uses the EXACT same decryption code as the enclave (decrypt_service_impl.py).
"""

import base64
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key


AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12


def decrypt_hybrid(encrypted_b64: str, private_key_pem: bytes) -> bytes:
    """Decrypt RSA-OAEP + AES-256-GCM hybrid encrypted data.

    This mirrors the enclave's DecryptServiceImpl.decrypt_combined_hybrid_data()
    """
    private_key = load_pem_private_key(private_key_pem, password=None)
    rsa_key_bytes = private_key.key_size // 8

    combined = base64.b64decode(encrypted_b64)

    encrypted_key = combined[:rsa_key_bytes]
    nonce = combined[rsa_key_bytes:rsa_key_bytes + GCM_NONCE_SIZE]
    ciphertext = combined[rsa_key_bytes + GCM_NONCE_SIZE:]  # includes the 16-byte tag

    # RSA-OAEP decrypt (SHA-256 hash, SHA-256 MGF1)
    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # AES-256-GCM decrypt; raises InvalidTag when the payload was modified
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def main():
    vectors_file = os.path.join(os.path.dirname(__file__), "test-vectors.json")

    if not os.path.exists(vectors_file):
        print(f"ERROR: {vectors_file} not found.")
        print("Run: go run ./scripts/generate-test-vectors")
        sys.exit(1)

    with open(vectors_file) as f:
        vectors = json.load(f)

    private_key_pem = vectors["private_key"].encode()

    passed = 0
    failed = 0

    for tv in vectors["test_vectors"]:
        name = tv["name"]
        encrypted = tv["encrypted"]
        expected = tv["plaintext"]

        try:
            decrypted = decrypt_hybrid(encrypted, private_key_pem)
            if decrypted.decode("utf-8") == expected:
                print(f"  PASS: {name}")
                passed += 1
            else:
                print(f"  FAIL: {name} — decrypted does not match expected")
                failed += 1
        except Exception as e:
            print(f"  FAIL: {name} — {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
