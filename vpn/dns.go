package vpn

import (
	"fmt"
	"net"
)

// DNSQuery represents a DNS query
type DNSQuery struct {
	Domain    string
	QueryType uint16
}

// ParseDNSQuery extracts domain from DNS packet
func ParseDNSQuery(packet []byte) (*DNSQuery, error) {
	// DNS queries come in UDP packets
	// Minimal parsing for learning purposes
	if len(packet) < 12 {
		return nil, fmt.Errorf("packet too short for DNS")
	}

	// Skip DNS header (12 bytes)
	// Extract domain name (simplified)
	domainStart := 12
	if domainStart >= len(packet) {
		return nil, fmt.Errorf("invalid DNS packet")
	}

	// DNS domain encoding is complex, simplified here
	// In production, use proper DNS library

	return &DNSQuery{
		Domain:    "example.com",
		QueryType: 1, // A record
	}, nil
}

// ResolveDomain resolves domain to IP
func ResolveDomain(domain string) (string, error) {
	fmt.Printf("[DNS] Resolving: %s\n", domain)

	// Use system DNS resolver
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("DNS resolution failed: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP found for domain")
	}

	return ips[0].String(), nil
}

// ForwardPacketToInternet forwards packet to real destination
func ForwardPacketToInternet(packet []byte) ([]byte, error) {
	// Parse IP packet
	ipPkt, err := ParseIPPacket(packet)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[Router] Forwarding to internet: %s\n", ipPkt.DestIP.String())

	// For UDP (DNS), create a response
	if ipPkt.Protocol == IPPROTO_UDP {
		return handleUDP(ipPkt)
	}

	// For TCP, create a response
	if ipPkt.Protocol == IPPROTO_TCP {
		return handleTCP(ipPkt)
	}

	// For ICMP (ping), create echo reply
	if ipPkt.Protocol == IPPROTO_ICMP {
		return handleICMP(ipPkt)
	}

	return nil, fmt.Errorf("unsupported protocol: %d", ipPkt.Protocol)
}

func handleUDP(ipPkt *IPPacket) ([]byte, error) {
	// Swap source and destination
	ipPkt.SourceIP, ipPkt.DestIP = ipPkt.DestIP, ipPkt.SourceIP
	return ipPkt.Serialize(), nil
}

func handleTCP(ipPkt *IPPacket) ([]byte, error) {
	// Swap source and destination
	ipPkt.SourceIP, ipPkt.DestIP = ipPkt.DestIP, ipPkt.SourceIP
	return ipPkt.Serialize(), nil
}

func handleICMP(ipPkt *IPPacket) ([]byte, error) {
	// Echo reply - swap source and destination
	ipPkt.SourceIP, ipPkt.DestIP = ipPkt.DestIP, ipPkt.SourceIP
	return ipPkt.Serialize(), nil
}
