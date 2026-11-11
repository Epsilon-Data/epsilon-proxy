package crypto

import (
	"errors"
	"testing"
	"time"
)

func TestFreshnessGuard(t *testing.T) {
	start := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	ms := func(t time.Time) uint64 { return uint64(t.UnixMilli()) }

	t.Run("accepts a recent document once", func(t *testing.T) {
		g := NewFreshnessGuard(5*time.Minute, func() time.Time { return start })
		if err := g.Accept("doc-a", ms(start.Add(-10*time.Second))); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if err := g.Accept("doc-a", ms(start.Add(-10*time.Second))); !errors.Is(err, ErrAttestationReplayed) {
			t.Fatalf("second use: got %v, want ErrAttestationReplayed", err)
		}
		if err := g.Accept("doc-b", ms(start.Add(-10*time.Second))); err != nil {
			t.Fatalf("another document: %v", err)
		}
	})

	t.Run("refuses a document older than the window", func(t *testing.T) {
		g := NewFreshnessGuard(5*time.Minute, func() time.Time { return start })
		if err := g.Accept("doc", ms(start.Add(-5*time.Minute-time.Second))); !errors.Is(err, ErrAttestationStale) {
			t.Fatalf("got %v, want ErrAttestationStale", err)
		}
		if err := g.Accept("doc-edge", ms(start.Add(-5*time.Minute))); err != nil {
			t.Fatalf("document at the edge of the window: %v", err)
		}
	})

	t.Run("refuses a document signed in the future beyond clock skew", func(t *testing.T) {
		g := NewFreshnessGuard(5*time.Minute, func() time.Time { return start })
		if err := g.Accept("doc", ms(start.Add(MaxClockSkew+time.Second))); !errors.Is(err, ErrAttestationStale) {
			t.Fatalf("got %v, want ErrAttestationStale", err)
		}
		if err := g.Accept("doc-skew", ms(start.Add(MaxClockSkew))); err != nil {
			t.Fatalf("document within clock skew: %v", err)
		}
	})

	t.Run("a used document stays refused after its entry is dropped", func(t *testing.T) {
		now := start
		g := NewFreshnessGuard(5*time.Minute, func() time.Time { return now })
		signedAt := ms(start)
		if err := g.Accept("doc", signedAt); err != nil {
			t.Fatal(err)
		}
		now = start.Add(4 * time.Minute)
		if err := g.Accept("doc", signedAt); !errors.Is(err, ErrAttestationReplayed) {
			t.Fatalf("inside the window: got %v, want ErrAttestationReplayed", err)
		}
		now = start.Add(6 * time.Minute)
		if err := g.Accept("other", ms(now)); err != nil {
			t.Fatal(err)
		}
		if len(g.used) != 1 {
			t.Fatalf("expired entries kept: %d entries", len(g.used))
		}
		if err := g.Accept("doc", signedAt); !errors.Is(err, ErrAttestationStale) {
			t.Fatalf("after the window: got %v, want ErrAttestationStale", err)
		}
	})
}
