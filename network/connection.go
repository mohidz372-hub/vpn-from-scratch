package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"vpn/crypto"
)

type SecureConnection struct {
	conn   net.Conn
	encKey *crypto.EncryptionKey
}

// NewSecureConnection wraps a network connection
func NewSecureConnection(conn net.Conn, encKey *crypto.EncryptionKey) *SecureConnection {
	return &SecureConnection{
		conn:   conn,
		encKey: encKey,
	}
}

// Send encrypts and sends data
func (sc *SecureConnection) Send(data []byte) error {
	payload, err := sc.encKey.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	serialized := payload.Serialize()

	_, err = sc.conn.Write(serialized)
	return err
}

// Receive receives and decrypts data
func (sc *SecureConnection) Receive() ([]byte, error) {
	// Read exactly 4 bytes for total length
	lenBuf := make([]byte, 4)
	bytesRead := 0
	for bytesRead < 4 {
		n, err := sc.conn.Read(lenBuf[bytesRead:])
		if err != nil {
			return nil, err
		}
		bytesRead += n
	}

	totalLen := binary.BigEndian.Uint32(lenBuf)

	// Read exactly totalLen bytes
	payload := make([]byte, totalLen)
	bytesRead = 0
	for bytesRead < len(payload) {
		n, err := sc.conn.Read(payload[bytesRead:])
		if err != nil {
			return nil, err
		}
		bytesRead += n
	}

	// Combine length + payload for deserialization
	fullData := append(lenBuf, payload...)

	parsedPayload, err := crypto.DeserializePayload(fullData)
	if err != nil {
		return nil, fmt.Errorf("deserialization failed: %v", err)
	}

	plaintext, err := sc.encKey.Decrypt(parsedPayload)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return plaintext, nil
}

// Close closes the connection
func (sc *SecureConnection) Close() error {
	return sc.conn.Close()
}
