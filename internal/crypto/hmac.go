package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

const MaxTimestampDrift = 300 // 5 minutes

// SignRequest creates an HMAC-SHA256 signature for request authentication.
func SignRequest(proxyToken, requestID, sessionID string, timestamp int64) string {
	message := fmt.Sprintf("%s%s%d", requestID, sessionID, timestamp)
	mac := hmac.New(sha256.New, []byte(proxyToken))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies the HMAC-SHA256 signature and timestamp freshness.
func VerifySignature(proxyToken, requestID, sessionID string, timestamp int64, signature string) error {
	// Check timestamp freshness
	now := time.Now().Unix()
	drift := math.Abs(float64(now - timestamp))
	if drift > MaxTimestampDrift {
		return fmt.Errorf("request timestamp too old: %.0fs drift (max %ds)", drift, MaxTimestampDrift)
	}

	expected := SignRequest(proxyToken, requestID, sessionID, timestamp)
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return fmt.Errorf("HMAC signature mismatch")
	}

	return nil
}
