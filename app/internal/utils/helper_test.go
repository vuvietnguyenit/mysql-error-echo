package utils_test

import (
	"encoding/hex"
	"testing"

	"git.itim.vn/docker/mysql-response-trace/app/internal/utils"
)

func TestParseMySQLPacket(t *testing.T) {
	hexDump := "33000003ff8604233038533031476f7420616e206572726f722072656164696e6720636f6d6d756e69636174696f6e207061636b657473"
	raw, _ := hex.DecodeString(hexDump)
	pkt, err := utils.ParseMySQLPacket(raw)
	if err != nil {
		panic(err)
	}
	t.Logf("result: %v", pkt)

}

func TestIsMySQLErrorMessage(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte
		want bool
	}{
		// ✅ Valid MySQL error messages
		{"access denied", []byte("H#28000Access denied for user 'root'@'127.0.0.1' (using password: YES)"), true},
		{"unknown database", []byte("#42000Unknown database 'testdb'"), true},
		{"syntax error", []byte("#42000You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"), true},
		{"foreign key constraint", []byte("#23000Cannot add or update a child row: a foreign key constraint fails"), true},
		{"server shutdown", []byte("#08S01Lost connection to MySQL server during query"), true},
		{"data too long", []byte("#22001Data too long for column 'name' at row 1"), true},
		{"duplicate entry", []byte("#23000Duplicate entry '123' for key 'PRIMARY'"), true},
		{"no database selected", []byte("#3D000No database selected"), true},
		{"unknown column", []byte("#42S22Unknown column 'username' in 'field list'"), true},
		{"bad null", []byte("#23000Column 'email' cannot be null"), true},

		// ❌ Invalid / noise cases
		{"no hash", []byte("12345"), false},
		{"hash with space", []byte("#12 34"), false},
		{"random binary", []byte("hc op\"lqďG%F5B  nC@+ZQPU'H誢0Ϊ>Hw^fUo~Oj.hZ{;͎As뮧Z[n7>SR2#уh3t5>]TU0u]=!"), false},
		{"partial fragment", []byte("#280"), false},
		{"non error text", []byte("OK"), false},
		{"empty", []byte(""), false},
		{"mysql ok packet", []byte("\x00\x00\x00\x02\x00\x00\x00\x02"), false},
		{"result set row", []byte("user_id name email"), false},
		{"prepared stmt binary", []byte{0x01, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00}, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := utils.IsMySQLErrorMessage(tc.msg)
			if got != tc.want {
				t.Fatalf("IsMySQLErrorMessage(%q) = %v; want %v", tc.msg, got, tc.want)
			}
		})
	}
}
