package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
)

type MySQLPayload []byte

type MySQLPacket struct {
	PayloadLength uint32
	SequenceID    byte
	Payload       MySQLPayload
}

func (m *MySQLPayload) ToString() string {
	return string(*m)
}

func (m MySQLPacket) String() string {
	return fmt.Sprintf("Length: %d, SeqID: %d, Payload: %s", m.PayloadLength, m.SequenceID, string(m.Payload))
}

func ParseMySQLPacket(data []byte) (*MySQLPacket, error) {
	// Dummy implementation, replace with actual parsing logic
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}
	// MySQL uses 3 bytes for length (little endian), pad to 4
	length := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
	seqID := data[3]

	// I just want to make sure the data length is enough
	if len(data) < int(4+length) {
		return nil, fmt.Errorf("incomplete packet: expected %d bytes payload, got %d", length, len(data)-4)
	}

	payload := data[4 : 4+length]
	return &MySQLPacket{
		PayloadLength: length,
		SequenceID:    seqID,
		Payload:       payload,
	}, nil

}

func IntToIP(ip uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

var mysqlErrorPattern = regexp.MustCompile(`#(?:[A-Z0-9]{5})`)

func IsMySQLErrorMessage(msg []byte) bool {
	return mysqlErrorPattern.Match(msg)
}
