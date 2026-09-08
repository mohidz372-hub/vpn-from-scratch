package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// KeyExchange implements Diffie-Hellman key exchange
type KeyExchange struct {
	P  *big.Int // Prime modulus
	G  *big.Int // Generator
	Xa *big.Int // Our private key
	Ya *big.Int // Our public key
	Yb *big.Int // Peer's public key
}

// NewKeyExchange creates a new key exchange session
func NewKeyExchange() *KeyExchange {
	// RFC 2409 1024-bit MODP group
	pStr := "179769313486231590772930519466302748958373064366542817068865620592537282042619752885715692650978911635494265564552220490251748938883437565705368859333622537414592230335988936316747514144292706671971060256843873674603865028276831633279797279880220758405326039594560171404067222586842841616518217395968171784546957026271631064546150257207402481637773389638550695260668341137273873722928956493547025762283997392313968145784851852889562750402684515271171138725149950870180695567324662717297869222846453085329949786365290609600033986495698233102434378912159146865779787604012148033282857914152896979649227936825839935803262"
	gStr := "2"

	p := new(big.Int)
	g := new(big.Int)
	p.SetString(pStr, 10)
	g.SetString(gStr, 10)

	// Generate random private key
	xa, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	xa.Add(xa, big.NewInt(1))

	// Calculate public key: Ya = G^Xa mod P
	ya := new(big.Int)
	ya.Exp(g, xa, p)

	return &KeyExchange{
		P:  p,
		G:  g,
		Xa: xa,
		Ya: ya,
	}
}

// GetPublicKey returns our public key with length prefix
func (ke *KeyExchange) GetPublicKey() []byte {
	keyBytes := ke.Ya.Bytes()
	// Length prefix (4 bytes) + key bytes
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(keyBytes)))
	return append(lenBuf, keyBytes...)
}

// ComputeSharedSecret calculates shared secret from peer's public key (with length prefix)
func (ke *KeyExchange) ComputeSharedSecret(peerPublicKeyBytesWithLen []byte) ([]byte, error) {
	if len(peerPublicKeyBytesWithLen) < 4 {
		return nil, fmt.Errorf("public key too short")
	}

	keyLen := binary.BigEndian.Uint32(peerPublicKeyBytesWithLen[:4])
	if len(peerPublicKeyBytesWithLen) < 4+int(keyLen) {
		return nil, fmt.Errorf("public key length mismatch")
	}

	yb := new(big.Int)
	yb.SetBytes(peerPublicKeyBytesWithLen[4 : 4+keyLen])

	ke.Yb = yb

	// Compute shared secret: S = Yb^Xa mod P
	s := new(big.Int)
	s.Exp(ke.Yb, ke.Xa, ke.P)

	return s.Bytes(), nil
}

// DeriveEncryptionKey derives encryption key from shared secret
func DeriveEncryptionKey(sharedSecret []byte) *EncryptionKey {
	// Use HMAC-based key derivation
	h := sha256.New()
	h.Write(sharedSecret)
	hash1 := h.Sum(nil) // 32 bytes

	h = sha256.New()
	h.Write(append(sharedSecret, hash1...))
	hash2 := h.Sum(nil)

	return &EncryptionKey{
		AESKey:  hash1, // 32 bytes for AES-256
		HMACKey: hash2, // 32 bytes for HMAC
	}
}
