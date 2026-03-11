package db

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxRowLimit is enforced on all queries to prevent DoS via huge result sets.
const MaxRowLimit = 50000

// blockedPatterns prevents access to system catalogs and dangerous operations.
var blockedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\binformation_schema\b`),
	regexp.MustCompile(`(?i)\bpg_catalog\b`),
	regexp.MustCompile(`(?i)\bpg_\w+\b`),
	regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|COPY)\b`),
	regexp.MustCompile(`(?i)\bINTO\s+OUTFILE\b`),
	regexp.MustCompile(`(?i)\bLOAD_FILE\b`),
	regexp.MustCompile(`(?i)\bpg_sleep\b`),
	regexp.MustCompile(`(?i)\bdblink\b`),
	regexp.MustCompile(`(?i)\bpg_read_file\b`),
	regexp.MustCompile(`(?i)\bpg_ls_dir\b`),
}

// ValidateQuery checks that the SQL query is a safe SELECT statement.
func ValidateQuery(sql string) error {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return fmt.Errorf("empty query")
	}

	// Must start with SELECT or WITH (for CTEs)
	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
		return fmt.Errorf("only SELECT queries are allowed")
	}

	// Block multiple statements (basic semicolon check)
	// Remove strings to avoid false positives on semicolons inside string literals
	stripped := stripStringLiterals(trimmed)
	if strings.Count(stripped, ";") > 1 || (strings.Count(stripped, ";") == 1 && !strings.HasSuffix(strings.TrimSpace(stripped), ";")) {
		return fmt.Errorf("multiple statements not allowed")
	}

	// Check blocked patterns
	for _, pattern := range blockedPatterns {
		if pattern.MatchString(stripped) {
			return fmt.Errorf("query contains blocked pattern: %s", pattern.String())
		}
	}

	return nil
}

// stripStringLiterals removes string content to avoid false positives.
func stripStringLiterals(sql string) string {
	result := make([]byte, 0, len(sql))
	inSingle := false
	inDouble := false

	for i := 0; i < len(sql); i++ {
		ch := sql[i]
		if ch == '\'' && !inDouble {
			if inSingle {
				// Check for escaped quote
				if i+1 < len(sql) && sql[i+1] == '\'' {
					i++ // skip escaped quote
					continue
				}
				inSingle = false
			} else {
				inSingle = true
			}
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble {
			result = append(result, ch)
		}
	}

	return string(result)
}
