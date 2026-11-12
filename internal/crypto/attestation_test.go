package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVerifyAttestationRefusesWithoutAnExpectedPCR0(t *testing.T) {
	// Refused before the document is read: no document passes without an expected image
	if _, err := VerifyAttestation("not-even-base64", ""); !errors.Is(err, ErrNoExpectedPCR0) {
		t.Fatalf("err = %v, want ErrNoExpectedPCR0", err)
	}
}

func TestMatchPCR0(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	expected := strings.Repeat("ab", 48)

	if err := matchPCR0(pcr0, expected); err != nil {
		t.Fatalf("matching PCR0 refused: %v", err)
	}
	if err := matchPCR0(pcr0, strings.ToUpper(expected)); err != nil {
		t.Fatalf("upper-case hex refused: %v", err)
	}
	if err := matchPCR0(pcr0, ""); !errors.Is(err, ErrNoExpectedPCR0) {
		t.Fatalf("empty expected PCR0: err = %v, want ErrNoExpectedPCR0", err)
	}

	refused := map[string]string{
		"another image":  strings.Repeat("ab", 47) + "ac",
		"shorter value":  strings.Repeat("ab", 32),
		"not hex":        strings.Repeat("zz", 48),
		"all-zero value": strings.Repeat("00", 48),
	}
	for name, value := range refused {
		if err := matchPCR0(pcr0, value); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
