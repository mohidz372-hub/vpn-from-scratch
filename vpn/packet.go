package vpn

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPPacket represents an IPv4 packet
type IPPacket struct {
	Version        byte
	HeaderLength   byte
	TOS            byte
	TotalLength    uint16
	ID             uint16
	Flags          byte
	FragmentOffset uint16
	TTL            byte
	Protocol       byte
	Checksum       uint16
	SourceIP       net.IP
	DestIP         net.IP
	Payload        []byte
}

// ParseIPPacket parses raw bytes into an IP packet
func ParseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short")
	}

	pkt := &IPPacket{
		Version:        data[0] >> 4,
		HeaderLength:   (data[0] & 0x0f) * 4,
		TOS:            data[1],
		TotalLength:    binary.BigEndian.Uint16(data[2:4]),
		ID:             binary.BigEndian.Uint16(data[4:6]),
		Flags:          data[6] >> 5,
		FragmentOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1fff,
		TTL:            data[8],
		Protocol:       data[9],
		Checksum:       binary.BigEndian.Uint16(data[10:12]),
		SourceIP:       net.IPv4(data[12], data[13], data[14], data[15]),
		DestIP:         net.IPv4(data[16], data[17], data[18], data[19]),
	}

	// Extract payload
	if len(data) > int(pkt.HeaderLength) {
		pkt.Payload = data[pkt.HeaderLength:]
	}

	return pkt, nil
}

// Serialize converts packet back to bytes
func (p *IPPacket) Serialize() []byte {
	// Create header (20 bytes minimum)
	header := make([]byte, 20)

	// Version (4 bits) + Header Length (4 bits)
	header[0] = (p.Version << 4) | (p.HeaderLength / 4)

	// TOS
	header[1] = p.TOS

	// Total Length
	binary.BigEndian.PutUint16(header[2:4], p.TotalLength)

	// ID
	binary.BigEndian.PutUint16(header[4:6], p.ID)

	// Flags + Fragment Offset
	binary.BigEndian.PutUint16(header[6:8], (uint16(p.Flags)<<13)|p.FragmentOffset)

	// TTL
	header[8] = p.TTL

	// Protocol
	header[9] = p.Protocol

	// Checksum (0 for now, should calculate)
	binary.BigEndian.PutUint16(header[10:12], 0)

	// Source IP
	copy(header[12:16], p.SourceIP.To4())

	// Dest IP
	copy(header[16:20], p.DestIP.To4())

	return append(header, p.Payload...)
}

// Protocol constants
const (
	IPPROTO_ICMP = 1
	IPPROTO_TCP  = 6
	IPPROTO_UDP  = 17
)

// ProtocolName returns human-readable protocol name
func ProtocolName(proto byte) string {
	switch proto {
	case IPPROTO_ICMP:
		return "ICMP"
	case IPPROTO_TCP:
		return "TCP"
	case IPPROTO_UDP:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown(%d)", proto)
	}
}
