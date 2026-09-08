package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"vpn/crypto"
	"vpn/network"
	"vpn/vpn"
)

type VPNTunnelServer struct {
	listener net.Listener
	running  bool
}

func startVPNTunnelServer(port string) error {
	fmt.Printf("[VPN Tunnel Server] Starting on :%s\n", port)

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	server := &VPNTunnelServer{
		listener: listener,
		running:  true,
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[VPN Tunnel Server] Shutting down...")
		server.Close()
		os.Exit(0)
	}()

	// Accept connections
	for server.running {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		fmt.Printf("[VPN Tunnel Server] New client: %s\n", conn.RemoteAddr())
		go server.handleTunnelClient(conn)
	}

	return nil
}

func (vts *VPNTunnelServer) handleTunnelClient(conn net.Conn) {
	defer conn.Close()

	// Perform key exchange
	fmt.Println("[VPN Tunnel Server] Starting key exchange...")

	serverKE := crypto.NewKeyExchange()
	serverPublicKey := serverKE.GetPublicKey()

	// Send server public key
	conn.Write(serverPublicKey)

	// Receive client public key length
	lenBuf := make([]byte, 4)
	conn.Read(lenBuf)

	// Receive client public key
	keyLen := binary.BigEndian.Uint32(lenBuf)
	clientPublicKeyBuf := make([]byte, keyLen)
	conn.Read(clientPublicKeyBuf)

	clientPublicKey := append(lenBuf, clientPublicKeyBuf...)

	// Compute shared secret
	sharedSecret, err := serverKE.ComputeSharedSecret(clientPublicKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return
	}

	// Derive encryption key
	encKey := crypto.DeriveEncryptionKey(sharedSecret)
	fmt.Println("[VPN Tunnel Server] ✓ Key exchange complete, tunnel established")

	// Create secure connection
	secConn := network.NewSecureConnection(conn, encKey)

	// Start receiving and forwarding packets
	vts.forwardPackets(secConn)
}

func (vts *VPNTunnelServer) forwardPackets(secConn *network.SecureConnection) {
	fmt.Println("[VPN Tunnel Server] Starting packet forwarding...")

	for vts.running {
		// Receive encrypted packet from client
		encryptedPacket, err := secConn.Receive()
		if err != nil {
			log.Printf("Receive error: %v", err)
			break
		}

		// Parse IP packet
		ipPkt, err := vpn.ParseIPPacket(encryptedPacket)
		if err != nil {
			log.Printf("Parse error: %v", err)
			continue
		}

		fmt.Printf("[VPN Tunnel Server] Received packet: %s -> %s (%s)\n",
			ipPkt.SourceIP, ipPkt.DestIP, vpn.ProtocolName(ipPkt.Protocol))

		// Forward to internet (or simulate)
		responsePacket, err := vpn.ForwardPacketToInternet(encryptedPacket)
		if err != nil {
			log.Printf("Forwarding error: %v", err)
			continue
		}

		// Send response back through tunnel
		err = secConn.Send(responsePacket)
		if err != nil {
			log.Printf("Send error: %v", err)
			break
		}

		// Parse response to log
		respPkt, _ := vpn.ParseIPPacket(responsePacket)
		if respPkt != nil {
			fmt.Printf("[VPN Tunnel Server] Sent response: %s -> %s\n",
				respPkt.SourceIP, respPkt.DestIP)
		}
	}

	fmt.Println("[VPN Tunnel Server] Client disconnected")
}

func (vts *VPNTunnelServer) Close() error {
	vts.running = false
	if vts.listener != nil {
		vts.listener.Close()
	}
	return nil
}
