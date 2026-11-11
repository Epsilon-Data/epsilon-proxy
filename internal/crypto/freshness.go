package crypto

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

var (
	// ErrAttestationStale means the document's signed time is outside the accepted window.
	ErrAttestationStale = errors.New("attestation document is outside the accepted time window")
	// ErrAttestationReplayed means the document was already used for a release.
	ErrAttestationReplayed = errors.New("attestation document was already used")
)

// MaxClockSkew is how far ahead of the proxy's clock a document's signed time may be.
const MaxClockSkew = time.Minute

// FreshnessGuard accepts an attestation document once, and only while it is recent.
// The time checked is the one signed by the enclave's hardware, not one chosen by the sender.
type FreshnessGuard struct {
	maxAge time.Duration
	now    func() time.Time

	mu   sync.Mutex
	used map[[sha256.Size]byte]time.Time // document digest -> time after which it is stale anyway
}

// NewFreshnessGuard returns a guard that accepts documents signed at most maxAge ago.
func NewFreshnessGuard(maxAge time.Duration, now func() time.Time) *FreshnessGuard {
	return &FreshnessGuard{maxAge: maxAge, now: now, used: make(map[[sha256.Size]byte]time.Time)}
}

// Accept records the first use of a recent document. It returns ErrAttestationStale for a
// document outside the window and ErrAttestationReplayed for one already accepted.
// signedAtMs is the timestamp of the verified document, in milliseconds since the Unix epoch.
func (g *FreshnessGuard) Accept(attestationB64 string, signedAtMs uint64) error {
	now := g.now()
	signedAt := time.UnixMilli(int64(signedAtMs))
	if now.Sub(signedAt) > g.maxAge || signedAt.Sub(now) > MaxClockSkew {
		return ErrAttestationStale
	}

	digest := sha256.Sum256([]byte(attestationB64))

	g.mu.Lock()
	defer g.mu.Unlock()
	for d, staleAfter := range g.used {
		if now.After(staleAfter) {
			delete(g.used, d)
		}
	}
	if _, seen := g.used[digest]; seen {
		return ErrAttestationReplayed
	}
	g.used[digest] = signedAt.Add(g.maxAge)
	return nil
}
