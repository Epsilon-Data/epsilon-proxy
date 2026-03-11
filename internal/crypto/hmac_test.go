package crypto

import (
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	token := "test_proxy_token_12345"
	requestID := "req_abc123"
	sessionID := "rsa-session-def456"
	timestamp := time.Now().Unix()

	sig := SignRequest(token, requestID, sessionID, timestamp)

	err := VerifySignature(token, requestID, sessionID, timestamp, sig)
	if err != nil {
		t.Fatalf("verify valid signature: %v", err)
	}
}

func TestVerifyRejectsWrongToken(t *testing.T) {
	requestID := "req_abc123"
	sessionID := "rsa-session-def456"
	timestamp := time.Now().Unix()

	sig := SignRequest("correct_token", requestID, sessionID, timestamp)

	err := VerifySignature("wrong_token", requestID, sessionID, timestamp, sig)
	if err == nil {
		t.Fatal("should reject wrong token")
	}
}

func TestVerifyRejectsOldTimestamp(t *testing.T) {
	token := "test_token"
	requestID := "req_abc123"
	sessionID := "rsa-session-def456"
	oldTimestamp := time.Now().Add(-10 * time.Minute).Unix()

	sig := SignRequest(token, requestID, sessionID, oldTimestamp)

	err := VerifySignature(token, requestID, sessionID, oldTimestamp, sig)
	if err == nil {
		t.Fatal("should reject old timestamp")
	}
}

func TestVerifyRejectsTamperedRequest(t *testing.T) {
	token := "test_token"
	timestamp := time.Now().Unix()

	sig := SignRequest(token, "req_original", "session_1", timestamp)

	err := VerifySignature(token, "req_tampered", "session_1", timestamp, sig)
	if err == nil {
		t.Fatal("should reject tampered request_id")
	}
}
