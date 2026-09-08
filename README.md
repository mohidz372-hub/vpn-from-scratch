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

vpn-from-scratch/
│
├── 📁 cmd/ # Executable entry points
│ ├── server/
│ │ ├── main.go # Server entry point & CLI
│ │ └── vpn_tunnel_server.go # Tunnel server logic
│ └── client/
│ ├── main.go # Client entry point & CLI
│ └── vpn_tunnel_client.go # Tunnel client logic
│
├── 📁 pkg/ # Public reusable packages
│ ├── crypto/
│ │ ├── crypto.go # AES-256-GCM encryption & serialization
│ │ └── keyexchange.go # Diffie-Hellman key exchange (1024-bit)
│ ├── network/
│ │ └── connection.go # Secure connection wrapper & protocol
│ ├── vpn/
│ │ ├── packet.go # IPv4 packet parsing & serialization
│ │ ├── dns.go # DNS handling & forwarding
│ │ └── wireguard.go # WireGuard device integration
│ └── tun/
│ └── wintun.go # WinTun device wrapper (Windows TUN)
│
├── 📁 internal/ # Private packages (project-specific)
│
├── 📁 examples/ # Example usage & demos
│ └── basic_tunnel.go # Simple tunnel demonstration
│
├── 📁 docs/ # Project documentation
│ ├── ARCHITECTURE.md # Detailed architecture overview
│ ├── SETUP.md # Installation & configuration guide
│ └── TROUBLESHOOTING.md # Common issues & solutions
│
├── 📁 scripts/ # Helper scripts & automation
│ ├── build.sh # Build binaries for all platforms
│ └── test.sh # Run test suite
│
├── 📁 cmd/tunnel_test/ # Testing utilities
│ └── main.go # Tunnel simulation tests
│
├── go.mod # Go module definition
├── go.sum # Go dependencies (auto-generated)
├── README.md # Project documentation (this file)
├── .gitignore # Git ignore patterns
└── LICENSE # MIT License

## Requirements

- **Go 1.18+**
- **Windows 10/11**
- **Admin Privileges** (for TUN device)
- **WinTun DLL** (automatic on first run)

## Installation

### Clone Repository
```bash
git clone https://github.com/mohidz372-hub/vpn-from-scratch.git
cd vpn-from-scratch
```

### Install Dependencies
```bash
go get golang.zx2c4.com/wireguard
```

### Download WinTun
1. Download from https://www.wintun.net/
2. Extract and copy `wintun.dll` from `bin/amd64/` to project root
3. Or copy to `C:\Windows\System32\wintun.dll`

### Build
```bash
go build -o server.exe ./server
go build -o client.exe ./client
```

## Usage

### Phase 1: Basic Encrypted Tunnel (No TUN)

**Terminal 1 - Server:**
```bash
go run ./server -mode=basic -port=9999
```

**Terminal 2 - Client:**
```bash
go run ./client -mode=basic -server=localhost:9999
```

Expected: Encrypted message exchange

### Phase 2b: Full Tunnel (Real TUN Device)

⚠️ **Requires Admin Privileges**

**Terminal 1 - Server (Admin):**
```bash
.\server.exe -mode=tunnel -port=9999
```

**Terminal 2 - Client (Admin):**
```bash
.\client.exe -mode=tunnel -server=localhost:9999
```

Expected: Real network packets tunneling through encrypted connection

## How It Works

### Key Exchange
1. Server generates random private key, computes public key
2. Client generates random private key, computes public key
3. They exchange public keys over the network
4. Both independently compute the same shared secret using Diffie-Hellman
5. Shared secret → encryption key using HKDF (SHA-256)

### Encryption
- Each packet encrypted with AES-256-GCM
- HMAC-SHA256 for integrity verification
- Random nonce per packet
- All communication is end-to-end encrypted

### Tunneling
- Packets captured from WinTun device
- Encrypted and sent through secure channel
- Server routes/forwards packets
- Responses encrypted and sent back
- Decrypted and written back to TUN device

## Security

- **Encryption:** AES-256-GCM (NIST-approved)
- **Key Exchange:** 1024-bit Diffie-Hellman
- **Authentication:** HMAC-SHA256
- **Integrity:** GCM built-in authentication
- **Forward Secrecy:** Per-packet random nonces

## Limitations

- Educational/Learning project (not production-ready)
- WinTun requires admin privileges
- No real internet forwarding (simulated routing)
- No DNS resolution
- IPv4 only
- Basic packet handling

## Learning Outcomes

Through building this VPN, you'll understand:
- ✅ Cryptographic key exchange (Diffie-Hellman)
- ✅ Symmetric encryption (AES)
- ✅ Message authentication (HMAC)
- ✅ Network packet handling
- ✅ TUN device programming
- ✅ VPN architecture and design
- ✅ Go networking and systems programming

## Future Enhancements

- [ ] Real internet routing with NAT
- [ ] DNS resolution through tunnel
- [ ] IPv6 support
- [ ] Linux support (with TUN/TAP)
- [ ] User authentication
- [ ] Connection pooling
- [ ] Performance optimization
- [ ] Compression support

## Testing

Run test program:
```bash
go run cmd/tunnel_test/main.go
```

Verify encryption works:
```bash
go run ./server -mode=basic -port=9999
go run ./client -mode=basic -server=localhost:9999
```

Monitor packets (requires admin):
```bash
.\server.exe -mode=tunnel -port=9999
.\client.exe -mode=tunnel -server=localhost:9999
```

## References

- [WireGuard](https://www.wireguard.com/)
- [Diffie-Hellman Key Exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [WinTun](https://www.wintun.net/)

## License

MIT License - Feel free to use for learning and educational purposes

## Disclaimer

This is an educational project for learning VPN concepts. Use only in controlled environments for learning purposes. Not recommended for production use or real privacy protection.

## Author

Built as a cybersecurity learning project.

---

**Note:** This VPN demonstrates core concepts but lacks production-ready features like real internet routing, DNS resolution, and connection state management. For actual VPN usage, consider WireGuard or OpenVPN.
