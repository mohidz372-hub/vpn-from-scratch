package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vpn/crypto"
	"vpn/network"
	"vpn/tun"
	"vpn/vpn"
)

type VPNTunnelClient struct {
	serverAddr string
	secConn    *network.SecureConnection
	tunDevice  *tun.WinTunDevice
	encKey     *crypto.EncryptionKey
	running    bool
	mutex      sync.Mutex
}

// ConnectToVPNTunnel connects to VPN server and sets up tunnel
func ConnectToVPNTunnel(serverAddr string) (*VPNTunnelClient, error) {
	fmt.Printf("[VPN Tunnel Client] Connecting to server: %s\n", serverAddr)

	// Connect to server
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	// Perform key exchange
	fmt.Println("[VPN Tunnel Client] Starting key exchange...")

	clientKE := crypto.NewKeyExchange()
	clientPublicKey := clientKE.GetPublicKey()

	// Receive server public key length
	serverLenBuf := make([]byte, 4)
	conn.Read(serverLenBuf)

	// Receive server public key
	serverKeyLen := 0
	for i := 0; i < 4; i++ {
		serverKeyLen = serverKeyLen*256 + int(serverLenBuf[i])
	}
	serverPublicKeyBuf := make([]byte, serverKeyLen)
	conn.Read(serverPublicKeyBuf)

	serverPublicKey := append(serverLenBuf, serverPublicKeyBuf...)

	// Send client public key
	conn.Write(clientPublicKey)

	// Compute shared secret
	sharedSecret, err := clientKE.ComputeSharedSecret(serverPublicKey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive encryption key
	encKey := crypto.DeriveEncryptionKey(sharedSecret)
	fmt.Println("[VPN Tunnel Client] ✓ Key exchange complete")

	// Create secure connection
	secConn := network.NewSecureConnection(conn, encKey)

	// Create TUN device
	fmt.Println("[VPN Tunnel Client] Creating TUN device...")
	tunDevice, err := tun.CreateWinTun("vpn0")
	if err != nil {
		secConn.Close()
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	// Configure IP
	fmt.Println("[VPN Tunnel Client] Configuring IP address...")
	err = tunDevice.ConfigureIP("10.0.0.2", "255.255.255.0")
	if err != nil {
		tunDevice.Close()
		secConn.Close()
		return nil, fmt.Errorf("failed to configure IP: %w", err)
	}

	fmt.Println("[VPN Tunnel Client] ✓ VPN tunnel established!")

	client := &VPNTunnelClient{
		serverAddr: serverAddr,
		secConn:    secConn,
		tunDevice:  tunDevice,
		encKey:     encKey,
		running:    true,
	}

	return client, nil
}

// Start starts the VPN tunnel
func (vtc *VPNTunnelClient) Start() error {
	fmt.Println("[VPN Tunnel Client] Starting tunnel...")

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[VPN Tunnel Client] Shutting down...")
		vtc.Close()
		os.Exit(0)
	}()

	// Start two goroutines:
	// 1. Read from TUN and send to server
	// 2. Read from server and write to TUN
	go vtc.tunToServer()
	go vtc.serverToTun()

	// Keep running
	select {}
}

// tunToServer reads packets from TUN and sends to server
func (vtc *VPNTunnelClient) tunToServer() {
	fmt.Println("[VPN Tunnel Client] TUN→Server thread started")

	for vtc.running {
		// Read packets from TUN
		packets, sizes, err := vtc.tunDevice.ReadPackets()
		if err != nil {
			log.Printf("TUN read error: %v", err)
			continue
		}

		// Process each packet
		for i, size := range sizes {
			if size == 0 {
				continue
			}

			packet := packets[i][:size]

			// Parse IP packet
			ipPkt, err := vpn.ParseIPPacket(packet)
			if err != nil {
				log.Printf("Parse error: %v", err)
				continue
			}

			fmt.Printf("[VPN Tunnel Client] TUN packet: %s -> %s (%s, %d bytes)\n",
				ipPkt.SourceIP, ipPkt.DestIP, vpn.ProtocolName(ipPkt.Protocol), size)

			// Encrypt and send through VPN tunnel
			if vtc.secConn != nil {
				err := vtc.secConn.Send(packet)
				if err != nil {
					log.Printf("Failed to send through tunnel: %v", err)
					vtc.running = false
					break
				}
			}
		}
	}

	fmt.Println("[VPN Tunnel Client] TUN→Server thread stopped")
}

// serverToTun reads from server and writes to TUN
func (vtc *VPNTunnelClient) serverToTun() {
	fmt.Println("[VPN Tunnel Client] Server→TUN thread started")

	for vtc.running {
		// Read encrypted packet from server
		response, err := vtc.secConn.Receive()
		if err != nil {
			log.Printf("Receive error: %v", err)
			vtc.running = false
			break
		}

		// Parse IP packet
		ipPkt, err := vpn.ParseIPPacket(response)
		if err != nil {
			log.Printf("Parse error: %v", err)
			continue
		}

		fmt.Printf("[VPN Tunnel Client] Response packet: %s -> %s (%s, %d bytes)\n",
			ipPkt.SourceIP, ipPkt.DestIP, vpn.ProtocolName(ipPkt.Protocol), len(response))

		// Write response back to TUN device
		err = vtc.tunDevice.WritePackets([][]byte{response})
		if err != nil {
			log.Printf("TUN write error: %v", err)
			vtc.running = false
			break
		}
	}

	fmt.Println("[VPN Tunnel Client] Server→TUN thread stopped")
}

// SendPacket sends a packet through the tunnel
func (vtc *VPNTunnelClient) SendPacket(packet []byte) error {
	vtc.mutex.Lock()
	defer vtc.mutex.Unlock()

	if !vtc.running {
		return fmt.Errorf("tunnel not running")
	}

	// Parse packet
	ipPkt, err := vpn.ParseIPPacket(packet)
	if err != nil {
		return err
	}

	fmt.Printf("[VPN Tunnel Client] Sending packet: %s -> %s (%s)\n",
		ipPkt.SourceIP, ipPkt.DestIP, vpn.ProtocolName(ipPkt.Protocol))

	// Encrypt and send through tunnel
	return vtc.secConn.Send(packet)
}

// ReceivePacket receives a packet from the tunnel
func (vtc *VPNTunnelClient) ReceivePacket() ([]byte, error) {
	vtc.mutex.Lock()
	defer vtc.mutex.Unlock()

	if !vtc.running {
		return nil, fmt.Errorf("tunnel not running")
	}

	// Receive and decrypt from tunnel
	packet, err := vtc.secConn.Receive()
	if err != nil {
		return nil, err
	}

	// Parse packet
	ipPkt, err := vpn.ParseIPPacket(packet)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[VPN Tunnel Client] Received packet: %s -> %s (%s)\n",
		ipPkt.SourceIP, ipPkt.DestIP, vpn.ProtocolName(ipPkt.Protocol))

	return packet, nil
}

// Close closes the tunnel
func (vtc *VPNTunnelClient) Close() error {
	vtc.mutex.Lock()
	vtc.running = false
	vtc.mutex.Unlock()

	if vtc.tunDevice != nil {
		vtc.tunDevice.Close()
	}
	if vtc.secConn != nil {
		vtc.secConn.Close()
	}
	return nil
}
