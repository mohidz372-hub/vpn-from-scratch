# VPN from Scratch

A fully functional VPN built from scratch in Go, implementing encryption, key exchange, TUN device integration, and packet routing on Windows.

## Features

- ✅ **Diffie-Hellman Key Exchange** - Secure key negotiation
- ✅ **AES-256-GCM Encryption** - Military-grade encryption
- ✅ **HMAC-SHA256 Authentication** - Packet integrity verification
- ✅ **WinTun Device Integration** - Real packet tunneling on Windows
- ✅ **Packet Routing** - TCP, UDP, ICMP protocol support
- ✅ **WireGuard Integration** - Modern VPN framework

## Architecture

### Phase 1: Encryption & Key Exchange
- Diffie-Hellman key exchange for secure key negotiation
- AES-256-GCM for encryption
- HMAC for authentication
- Secure client-server tunnel

### Phase 2: Network Tunneling
- WinTun device creation and management
- Real packet capture from TUN device
- IP packet parsing and forwarding
- Bidirectional encrypted tunnel

### Phase 3: Routing & Internet
- WireGuard-based routing
- Packet forwarding logic
- DNS framework
- Protocol handling

## Project Structure
