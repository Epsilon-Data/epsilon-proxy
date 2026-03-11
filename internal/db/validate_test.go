package db

import (
	"testing"
)

func TestValidateQuery_Allowed(t *testing.T) {
	allowed := []string{
		"SELECT * FROM patients LIMIT 10",
		"SELECT id, name FROM users WHERE age > 18",
		"WITH cte AS (SELECT * FROM data) SELECT * FROM cte",
		"select count(*) from orders;",
		"SELECT * FROM my_table WHERE name = 'pg_catalog test'",
	}

	for _, q := range allowed {
		if err := ValidateQuery(q); err != nil {
			t.Errorf("expected query to be allowed: %s\n  got error: %v", q, err)
		}
	}
}

func TestValidateQuery_Blocked(t *testing.T) {
	blocked := []struct {
		query  string
		reason string
	}{
		{"", "empty"},
		{"INSERT INTO users VALUES (1)", "insert"},
		{"DELETE FROM users", "delete"},
		{"DROP TABLE users", "drop"},
		{"UPDATE users SET name='x'", "update"},
		{"SELECT * FROM information_schema.tables", "information_schema"},
		{"SELECT * FROM pg_catalog.pg_tables", "pg_catalog"},
		{"SELECT pg_sleep(100)", "pg_sleep"},
		{"SELECT * FROM dblink('host=evil.com')", "dblink"},
		{"SELECT * FROM users; DROP TABLE users", "multiple statements"},
		{"TRUNCATE users", "truncate"},
		{"CREATE TABLE evil (id int)", "create"},
		{"ALTER TABLE users ADD COLUMN x int", "alter"},
	}

	for _, tc := range blocked {
		if err := ValidateQuery(tc.query); err == nil {
			t.Errorf("expected query to be blocked (%s): %s", tc.reason, tc.query)
		}
	}
}
