package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// EncryptionKey holds AES key and HMAC key
type EncryptionKey struct {
	AESKey  []byte // 32 bytes for AES-256
	HMACKey []byte // 32 bytes for HMAC-SHA256
}

// Payload is what we send over the network
type Payload struct {
	IV         []byte // 16 bytes
	MAC        []byte // 32 bytes
	Ciphertext []byte // encrypted data
}

// GenerateKey creates a random key for AES-256
func GenerateKey() *EncryptionKey {
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)

	io.ReadFull(rand.Reader, aesKey)
	io.ReadFull(rand.Reader, hmacKey)

	return &EncryptionKey{
		AESKey:  aesKey,
		HMACKey: hmacKey,
	}
}

// Encrypt encrypts plaintext with AES-256-GCM
func (k *EncryptionKey) Encrypt(plaintext []byte) (*Payload, error) {
	// Create AES cipher
	block, err := aes.NewCipher(k.AESKey)
	if err != nil {
		return nil, err
	}

	// Use GCM mode (provides encryption + authentication)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce (IV)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Create HMAC for integrity verification
	mac := hmac.New(sha256.New, k.HMACKey)
	mac.Write(ciphertext)
	macSum := mac.Sum(nil)

	return &Payload{
		IV:         nonce,
		MAC:        macSum,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt decrypts ciphertext
func (k *EncryptionKey) Decrypt(payload *Payload) ([]byte, error) {
	// Verify MAC
	mac := hmac.New(sha256.New, k.HMACKey)
	mac.Write(payload.Ciphertext)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(payload.MAC, expectedMAC) {
		return nil, fmt.Errorf("MAC verification failed - packet tampered")
	}

	// Create AES cipher
	block, err := aes.NewCipher(k.AESKey)
	if err != nil {
		return nil, err
	}

	// Use GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, payload.IV, payload.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return plaintext, nil
}

// SerializePayload converts payload to bytes for transmission
func (p *Payload) Serialize() []byte {
	// Format: [total_len:4][iv_len:2][iv][mac_len:2][mac][ciphertext_len:4][ciphertext]

	// Calculate body
	body := make([]byte, 0)

	// IV length and data
	ivLen := make([]byte, 2)
	binary.BigEndian.PutUint16(ivLen, uint16(len(p.IV)))
	body = append(body, ivLen...)
	body = append(body, p.IV...)

	// MAC length and data
	macLen := make([]byte, 2)
	binary.BigEndian.PutUint16(macLen, uint16(len(p.MAC)))
	body = append(body, macLen...)
	body = append(body, p.MAC...)

	// Ciphertext length and data
	ctLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ctLen, uint32(len(p.Ciphertext)))
	body = append(body, ctLen...)
	body = append(body, p.Ciphertext...)

	// Add total length header
	totalLen := make([]byte, 4)
	binary.BigEndian.PutUint32(totalLen, uint32(len(body)))

	return append(totalLen, body...)
}

// DeserializePayload converts bytes back to payload
func DeserializePayload(data []byte) (*Payload, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("payload too short")
	}

	idx := 0

	// Read total length (skip, we already have all data)
	idx += 4

	// Read IV length
	ivLen := binary.BigEndian.Uint16(data[idx : idx+2])
	idx += 2
	if idx+int(ivLen) > len(data) {
		return nil, fmt.Errorf("invalid IV length")
	}
	iv := data[idx : idx+int(ivLen)]
	idx += int(ivLen)

	// Read MAC length
	macLen := binary.BigEndian.Uint16(data[idx : idx+2])
	idx += 2
	if idx+int(macLen) > len(data) {
		return nil, fmt.Errorf("invalid MAC length")
	}
	mac := data[idx : idx+int(macLen)]
	idx += int(macLen)

	// Read ciphertext length
	ctLen := binary.BigEndian.Uint32(data[idx : idx+4])
	idx += 4
	if idx+int(ctLen) > len(data) {
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	ciphertext := data[idx : idx+int(ctLen)]

	return &Payload{
		IV:         iv,
		MAC:        mac,
		Ciphertext: ciphertext,
	}, nil
}
