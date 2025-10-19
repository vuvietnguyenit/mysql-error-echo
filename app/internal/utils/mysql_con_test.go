package utils_test

// mysql_test_harness.go

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

var (
	mysqlDSN   string
	testTarget string
)

const timeout = 5 * time.Second

// TestCase describes a single test to run against the server.
type TestCase struct {
	Name          string   // test name
	SetupSQL      []string // SQL statements to run before QuerySQL (ignored if nil)
	QuerySQL      string   // the SQL to provoke an error (or not)
	ExpectError   bool     // whether we expect a server error response
	ExpectedCodes []uint16 // optional: list of MySQL error numbers we expect (e.g. 1045)
	// Note: leave ExpectedCodes nil to accept any error response.
}

func RunTestCase(db *sql.DB, tc TestCase) (string, error) {
	// Run setup statements if any (ignore errors from setup tear-down items)
	if tc.SetupSQL != nil {
		for _, s := range tc.SetupSQL {
			_, err := db.Exec(s)
			if err != nil {
				// Non-fatal for setup, but log it
				log.Printf("[setup][%s] statement failed: %s -> %v", tc.Name, s, err)
			}
		}
	}

	// Execute the query (use Exec so statements like INSERT/USE work)
	_, err := db.Exec(tc.QuerySQL)

	// If no error and we expected none -> success
	if err == nil {
		if tc.ExpectError {
			return "no error (expected error)", fmt.Errorf("expected server error but got none")
		}
		return "ok (no error)", nil
	}

	// There was an error. Try to detect server-side error number (MySQLError)
	var msg string
	if mysqlErr, ok := err.(*mysql.MySQLError); ok {
		// We got a MySQL server error object
		msg = fmt.Sprintf("MySQL server error: number=%d message=%q", mysqlErr.Number, mysqlErr.Message)
		// Match expected codes if provided
		if tc.ExpectedCodes != nil {
			matched := false
			for _, c := range tc.ExpectedCodes {
				if c == mysqlErr.Number {
					matched = true
					break
				}
			}
			if matched {
				return msg, nil
			}
			return msg, fmt.Errorf("unexpected error code %d (expected %v)", mysqlErr.Number, tc.ExpectedCodes)
		}
		// expected codes not specified -> any server error is accepted
		if tc.ExpectError {
			return msg, nil
		}
		return msg, fmt.Errorf("unexpected server error: %v", mysqlErr)
	}

	// Not a typed MySQL error (could be network error, driver-level)
	msg = fmt.Sprintf("non-MySQL error: %v", err)
	if tc.ExpectError {
		// Accept generic error if we expected any error
		return msg, nil
	}
	return msg, err
}

func mustOpen(dsn string, timeout time.Duration) *sql.DB {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		log.Fatalf("bad DSN: %v", err)
	}
	// set some sane timeouts
	if cfg.Timeout == 0 {
		cfg.Timeout = timeout
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = timeout
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = timeout
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatalf("open mysql: %v", err)
	}
	// quick ping
	if err := db.Ping(); err != nil {
		log.Fatalf("ping mysql: %v", err)
	}
	return db
}

func TestWorkingDBConnection(t *testing.T) {
	db := mustOpen(mysqlDSN, timeout)
	defer db.Close()

	// Prepare a small ephemeral schema used by some testcases
	schemaSetup := []string{
		"DROP DATABASE IF EXISTS test_harness_db",
		"CREATE DATABASE test_harness_db",
		"USE test_harness_db",
		`CREATE TABLE users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(32) UNIQUE,
			email VARCHAR(100),
			team_id INT
		)`,
		`CREATE TABLE teams (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(32) UNIQUE
		)`,
		// create a foreign key sample (InnoDB assumed)
		`ALTER TABLE users ADD CONSTRAINT fk_team FOREIGN KEY (team_id) REFERENCES teams(id)`,
		// insert initial row
		`INSERT INTO teams (name) VALUES ('engineering')`,
	}

	for _, s := range schemaSetup {
		if _, err := db.Exec(s); err != nil {
			// some servers may not allow FK or alter; log and continue
			log.Printf("[schema] exec failed: %v -> %v", s, err)
		}
	}

	// Table of realistic testcases
	tests := []TestCase{
		// Access denied (you can cause this by connecting with wrong creds,
		// but here we emulate by using GRANT-restricted steps is complex).
		// Instead, instruct user to run this test by connecting as wrong user:
		{
			Name:          "access denied (connect with bad creds)",
			SetupSQL:      nil,
			QuerySQL:      "SELECT 1",
			ExpectError:   true,
			ExpectedCodes: []uint16{1045},
		},
		// Unknown database
		{"unknown database", nil, "USE not_exist_db", true, []uint16{1049}},
		// Syntax error
		{"syntax error", nil, "SELECT * FORM users", true, []uint16{1064}},
		// Unknown table
		{"unknown table", nil, "SELECT * FROM no_such_table", true, []uint16{1146}},
		// Unknown column
		{"unknown column", nil, "SELECT unknown_col FROM users", true, []uint16{1054}},
		// No database selected (issue query without using DB)
		{"no database selected", []string{"USE test_harness_db"}, "USE ", true, []uint16{1046}}, // demo alternative
		// Data too long
		{"data too long", []string{"USE test_harness_db"}, "INSERT INTO users (username) VALUES ('" + longString(300) + "')", true, []uint16{1406}},
		// Duplicate entry for unique key
		{"duplicate entry", []string{"USE test_harness_db", "INSERT INTO users (username) VALUES ('dupeuser')"}, "INSERT INTO users (username) VALUES ('dupeuser')", true, []uint16{1062, 23000}},
		// Foreign key constraint
		{"foreign key constraint", []string{"USE test_harness_db"}, "INSERT INTO users (username, team_id) VALUES ('bob', 999999)", true, []uint16{1452, 1451, 1216}},
		// Column cannot be null
		{"column cannot be null", []string{"USE test_harness_db"}, "INSERT INTO users (username, email) VALUES (NULL, NULL)", true, []uint16{1048, 1048}},
		// Lost connection (simulate by closing DB after starting a long query)
		// We will create a separate test that intentionally times out or closes connection.
	}

	// NOTE: Some error numbers depend on server version and storage engine,
	// so test harness accepts multiple candidate codes for a case.

	fmt.Println("Running testcases...")
	for _, tc := range tests {
		// For the "access denied (bad creds)" test instruct user to run a separate process with wrong DSN.
		if tc.Name == "access denied (connect with bad creds)" {
			fmt.Printf("[SKIP] %s - to run this, call program with a DSN that uses wrong credentials\n", tc.Name)
			continue
		}

		// Build a TestCase object as expected by RunTestCase helper
		tcase := TestCase{
			Name:          tc.Name,
			SetupSQL:      tc.SetupSQL,
			QuerySQL:      tc.QuerySQL,
			ExpectError:   tc.ExpectError,
			ExpectedCodes: tc.ExpectedCodes,
		}

		desc := fmt.Sprintf("[%s] %s", time.Now().UTC().Format(time.RFC3339), tcase.Name)
		fmt.Println(desc)
		msg, err := RunTestCase(db, tcase)
		if err != nil {
			fmt.Printf(" -> RESULT: FAIL: %s | detail: %v\n", msg, err)
		} else {
			fmt.Printf(" -> RESULT: OK: %s\n", msg)
		}

		// small pause so eBPF captures are discrete
		time.Sleep(300 * time.Millisecond)
	}

	fmt.Println("Completed.")
}

func init() {
	flag.StringVar(&mysqlDSN, "dsn", "", "MySQL DSN, e.g. user:pass@tcp(localhost:3306)/")
	flag.StringVar(&testTarget, "target", "all", "Which test target to run (e.g. syntax, auth, all)")
}

func TestMain(m *testing.M) {
	log.Printf("DSN = %q", mysqlDSN)
	os.Exit(m.Run())
}

// helper to make a long string of size n
func longString(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = 'a' + byte(i%26)
	}
	return string(b)
}
