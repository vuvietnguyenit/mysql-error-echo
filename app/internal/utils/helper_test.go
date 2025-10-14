package utils_test

import (
	"encoding/hex"
	"testing"

	"git.itim.vn/docker/mysql-connection-trace/app/internal/utils"
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
