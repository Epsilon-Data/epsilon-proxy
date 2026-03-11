package db

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/Epsilon-Data/epsilon-proxy/internal/config"
)

type Client struct {
	cfg config.DatabaseConfig
}

type QueryResult struct {
	CSV      []byte
	RowCount int
	ColCount int
	Duration time.Duration
}

func New(cfg config.DatabaseConfig) *Client {
	return &Client{cfg: cfg}
}

// Ping tests database connectivity.
func (c *Client) Ping(ctx context.Context) error {
	db, err := c.connect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.PingContext(ctx)
}

// Query executes a SQL query and returns the result as CSV bytes.
func (c *Client) Query(ctx context.Context, sqlQuery string) (*QueryResult, error) {
	db, err := c.connect()
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer db.Close()

	// Set read-only transaction for safety
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read-only tx: %w", err)
	}
	defer tx.Rollback()

	start := time.Now()

	rows, err := tx.QueryContext(ctx, sqlQuery)
	if err != nil {
		return nil, fmt.Errorf("execute query: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("get columns: %w", err)
	}

	// Build CSV in memory
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	if err := writer.Write(columns); err != nil {
		return nil, fmt.Errorf("write CSV header: %w", err)
	}

	// Write rows
	rowCount := 0
	scanArgs := make([]any, len(columns))
	scanVals := make([]sql.NullString, len(columns))
	for i := range scanArgs {
		scanArgs[i] = &scanVals[i]
	}

	for rows.Next() {
		if rowCount >= MaxRowLimit {
			return nil, fmt.Errorf("result exceeds maximum row limit (%d rows)", MaxRowLimit)
		}

		if err := rows.Scan(scanArgs...); err != nil {
			return nil, fmt.Errorf("scan row %d: %w", rowCount, err)
		}

		record := make([]string, len(columns))
		for i, v := range scanVals {
			if v.Valid {
				record[i] = v.String
			}
		}

		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("write CSV row %d: %w", rowCount, err)
		}
		rowCount++
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flush CSV: %w", err)
	}

	duration := time.Since(start)

	return &QueryResult{
		CSV:      []byte(buf.String()),
		RowCount: rowCount,
		ColCount: len(columns),
		Duration: duration,
	}, nil
}

func (c *Client) connect() (*sql.DB, error) {
	connStr := c.cfg.URL
	if c.cfg.SSLMode != "" && !strings.Contains(connStr, "sslmode=") {
		sep := "?"
		if strings.Contains(connStr, "?") {
			sep = "&"
		}
		connStr += sep + "sslmode=" + c.cfg.SSLMode
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	db.SetMaxOpenConns(c.cfg.MaxConnections)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}
