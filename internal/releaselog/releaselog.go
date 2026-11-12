// Package releaselog keeps the data custodian's own record of every data release.
//
// One JSON line is appended, and synced to disk, for each extract the proxy
// encrypts for an enclave. extract_sha256 is the SHA-256 of the plaintext CSV;
// the enclave signs the same digest as dataset_hash in its record of the run,
// so the custodian can check what a run was given against this file.
package releaselog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one release.
type Entry struct {
	Time          string `json:"time"`
	RequestID     string `json:"request_id"`
	SessionID     string `json:"session_id"`
	Attested      bool   `json:"attested"` // false only in dev mode
	PCR0          string `json:"pcr0"`
	ModuleID      string `json:"module_id"`
	SQLQuery      string `json:"sql_query"`
	RowCount      int    `json:"row_count"`
	ColumnCount   int    `json:"column_count"`
	ExtractSHA256 string `json:"extract_sha256"`
}

// Log appends entries to a file on the custodian's machine.
type Log struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

func New(path string) *Log {
	return &Log{path: path, now: time.Now}
}

func (l *Log) Path() string {
	return l.path
}

// ExtractDigest is the SHA-256 of a plaintext extract, in lower-case hex.
func ExtractDigest(extract []byte) string {
	sum := sha256.Sum256(extract)
	return hex.EncodeToString(sum[:])
}

// Check reports whether the log can be written, without adding an entry.
func (l *Log) Check() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := l.open()
	if err != nil {
		return err
	}
	return f.Close()
}

// Record appends the entry and syncs it to disk. It sets the entry's time.
// The caller must not release the extract when Record fails.
func (l *Log) Record(entry Entry) error {
	entry.Time = l.now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode release log entry: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := l.open()
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("write release log %s: %w", l.path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync release log %s: %w", l.path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close release log %s: %w", l.path, err)
	}
	return nil
}

func (l *Log) open() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		return nil, fmt.Errorf("create release log directory: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open release log %s: %w", l.path, err)
	}
	return f, nil
}
