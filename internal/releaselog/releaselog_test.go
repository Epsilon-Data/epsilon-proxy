package releaselog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readEntries(t *testing.T, path string) []Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("line %q: %v", scanner.Text(), err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestRecordAppendsOneLinePerRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "releases.log")
	l := New(path)
	l.now = func() time.Time { return time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC) }

	first := Entry{RequestID: "req-1", Attested: true, PCR0: "ab", SQLQuery: "SELECT age\nFROM patients", RowCount: 2, ExtractSHA256: ExtractDigest([]byte("age\n1\n2\n"))}
	second := Entry{RequestID: "req-2", Attested: true, PCR0: "ab", SQLQuery: "SELECT 1", RowCount: 1}
	for _, entry := range []Entry{first, second} {
		if err := l.Record(entry); err != nil {
			t.Fatal(err)
		}
	}
	// A new Log on the same file appends: restarting the proxy keeps earlier releases
	if err := New(path).Record(Entry{RequestID: "req-3"}); err != nil {
		t.Fatal(err)
	}

	entries := readEntries(t, path)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	first.Time = "2026-11-12T09:30:00Z"
	if entries[0] != first {
		t.Fatalf("entry = %+v, want %+v", entries[0], first)
	}
	if entries[2].RequestID != "req-3" {
		t.Fatalf("third entry = %+v", entries[2])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestExtractDigestIsSHA256Hex(t *testing.T) {
	// SHA-256 of "abc" (FIPS 180-2 test vector)
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := ExtractDigest([]byte("abc")); got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
}

func TestRecordAndCheckFailWhenTheLogCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	l := New(filepath.Join(blocker, "releases.log"))

	if err := l.Check(); err == nil {
		t.Fatal("Check succeeded on an unwritable path")
	}
	if err := l.Record(Entry{RequestID: "req-1"}); err == nil {
		t.Fatal("Record succeeded on an unwritable path")
	}
}

func TestCheckAddsNoEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "releases.log")
	if err := New(path).Check(); err != nil {
		t.Fatal(err)
	}
	if entries := readEntries(t, path); len(entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(entries))
	}
}
