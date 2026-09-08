package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
	"vpn/crypto"
	"vpn/network"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	mode := flag.String("mode", "basic", "Mode: basic or tunnel")
	server := flag.String("server", "localhost:9999", "Server address")
	flag.Parse()

	if *mode == "tunnel" {
		fmt.Println("[VPN] Starting Phase 2b: Full Tunnel Client")
		fmt.Println("[VPN] This requires ADMIN privileges for TUN device!")

		client, err := ConnectToVPNTunnel(*server)
		if err != nil {
			log.Fatalf("Failed to connect to VPN tunnel: %w", err)
		}

		err = client.Start()
		if err != nil {
			log.Fatalf("Tunnel client failed: %v", err)
		}
	} else {
		// Original basic mode
		fmt.Println("[CLIENT] VPN Client Starting...")
		fmt.Println("[CLIENT] Connecting to server: localhost:9999")

		conn, err := net.Dial("tcp", "localhost:9999")
		if err != nil {
			log.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()

		fmt.Println("[CLIENT] ✓ Connected to server")

		clientKE := crypto.NewKeyExchange()
		clientPublicKey := clientKE.GetPublicKey()

		fmt.Println("[CLIENT] Created key exchange")
		fmt.Printf("[CLIENT] Public key length: %d bytes\n", len(clientPublicKey))

		fmt.Println("[CLIENT] Waiting for server public key...")
		serverLenBuf := make([]byte, 4)
		conn.Read(serverLenBuf)

		serverKeyLen := binary.BigEndian.Uint32(serverLenBuf)
		serverPublicKeyBuf := make([]byte, serverKeyLen)
		conn.Read(serverPublicKeyBuf)

		serverPublicKey := append(serverLenBuf, serverPublicKeyBuf...)
		fmt.Printf("[CLIENT] ✓ Received server public key (%d bytes)\n", len(serverPublicKey))

		fmt.Println("[CLIENT] Sending client public key...")
		conn.Write(clientPublicKey)

		fmt.Println("[CLIENT] ✓ Sent client public key")

		fmt.Println("[CLIENT] Computing shared secret...")
		sharedSecret, err := clientKE.ComputeSharedSecret(serverPublicKey)
		if err != nil {
			log.Fatalf("Failed to compute shared secret: %v", err)
		}

		fmt.Printf("[CLIENT] ✓ Computed shared secret (%d bytes)\n", len(sharedSecret))

		encKey := crypto.DeriveEncryptionKey(sharedSecret)
		fmt.Println("[CLIENT] Derived encryption key")
		fmt.Println("[CLIENT] ✓ Secure channel established!")

		secConn := network.NewSecureConnection(conn, encKey)

		fmt.Println("[CLIENT] Waiting for server message...")
		received, err := secConn.Receive()
		if err != nil {
			log.Fatalf("Failed to receive: %v", err)
		}

		fmt.Printf("[CLIENT] ✓ Received encrypted message: \"%s\"\n", string(received))

		time.Sleep(500 * time.Millisecond)

		message := []byte("Thanks for the secure connection!")
		fmt.Printf("[CLIENT] Sending encrypted message: \"%s\"\n", string(message))

		err = secConn.Send(message)
		if err != nil {
			log.Fatalf("Failed to send: %v", err)
		}

		fmt.Println("[CLIENT] ✓ Message sent (encrypted)")
		fmt.Println("[CLIENT] Connection closing...")
	}
}
