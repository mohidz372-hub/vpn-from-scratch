package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"vpn/crypto"
	"vpn/network"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	mode := flag.String("mode", "basic", "Mode: basic or tunnel")
	port := flag.String("port", "9999", "Port to listen on")
	flag.Parse()

	if *mode == "tunnel" {
		fmt.Println("[VPN] Starting Phase 2b: Full Tunnel Server")
		fmt.Println("[VPN] This requires ADMIN privileges for TUN device!")
		err := startVPNTunnelServer(*port)
		if err != nil {
			log.Fatalf("Tunnel server failed: %v", err)
		}
	} else {
		// Original basic mode
		listener, err := net.Listen("tcp", ":"+*port)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		defer listener.Close()

		fmt.Println("[SERVER] Listening on :" + *port)
		fmt.Println("[SERVER] Waiting for client connection...")

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}

			fmt.Printf("[SERVER] New connection from %s\n", conn.RemoteAddr())
			go handleClient(conn)
		}
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	serverKE := crypto.NewKeyExchange()
	serverPublicKey := serverKE.GetPublicKey()

	fmt.Println("[SERVER] Created key exchange")
	fmt.Printf("[SERVER] Public key length: %d bytes\n", len(serverPublicKey))
	fmt.Println("[SERVER] Sending public key to client...")

	_, err := conn.Write(serverPublicKey)
	if err != nil {
		log.Printf("Failed to send public key: %v", err)
		return
	}

	clientLenBuf := make([]byte, 4)
	_, err = conn.Read(clientLenBuf)
	if err != nil {
		log.Printf("Failed to read client key length: %v", err)
		return
	}

	keyLen := binary.BigEndian.Uint32(clientLenBuf)
	clientPublicKeyBuf := make([]byte, keyLen)
	_, err = conn.Read(clientPublicKeyBuf)
	if err != nil {
		log.Printf("Failed to read client public key: %v", err)
		return
	}

	clientPublicKey := append(clientLenBuf, clientPublicKeyBuf...)
	fmt.Printf("[SERVER] Received client public key (%d bytes)\n", len(clientPublicKey))

	sharedSecret, err := serverKE.ComputeSharedSecret(clientPublicKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return
	}

	fmt.Printf("[SERVER] Computed shared secret (%d bytes)\n", len(sharedSecret))

	encKey := crypto.DeriveEncryptionKey(sharedSecret)
	fmt.Println("[SERVER] Derived encryption key")
	fmt.Println("[SERVER] ✓ Secure channel established!")

	secConn := network.NewSecureConnection(conn, encKey)

	message := []byte("Hello from server! Your VPN tunnel is secure.")
	fmt.Printf("[SERVER] Sending encrypted message: \"%s\"\n", string(message))

	err = secConn.Send(message)
	if err != nil {
		log.Printf("Failed to send: %v", err)
		return
	}

	fmt.Println("[SERVER] ✓ Message sent (encrypted)")

	fmt.Println("[SERVER] Waiting for client message...")
	received, err := secConn.Receive()
	if err != nil {
		log.Printf("Failed to receive: %v", err)
		return
	}

	fmt.Printf("[SERVER] ✓ Received encrypted message: \"%s\"\n", string(received))
	fmt.Println("[SERVER] Connection closing...")
}
