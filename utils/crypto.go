package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// Convert Ed25519 private key to X25519 private key
func ed25519PrivateKeyToX25519(ed25519Priv ed25519.PrivateKey) []byte {
	var x25519Priv [32]byte
	copy(x25519Priv[:], ed25519Priv.Seed())
	return x25519Priv[:]
}

// Convert Ed25519 public key to X25519 public key
func ed25519PublicKeyToX25519(ed25519Pub ed25519.PublicKey) ([]byte, error) {
	return curve25519.X25519(ed25519Pub[:], curve25519.Basepoint)
}

func GenerateSharedKey(ourPk ed25519.PrivateKey, serverPb ed25519.PublicKey) ([]byte, error) {
	// Convert Ed25519 keys to X25519 keys
	ourX25519Priv := ed25519PrivateKeyToX25519(ourPk)
	serverX25519Pub, err := ed25519PublicKeyToX25519(serverPb)
	if err != nil {
		return nil, err
	}

	// Generate shared secret
	sharedSecret, err := curve25519.X25519(ourX25519Priv, serverX25519Pub)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

func KeyIDEd25519(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key not 32 bytes")
	}

	magic := []byte{0xc6, 0xb4, 0x13, 0x48}
	hash := sha256.New()
	hash.Write(magic)
	hash.Write(key)
	s := hash.Sum(nil)

	return s, nil
}

// copied and modified a bit from tonutils-go
func BuildSharedCipher(key []byte, checksum []byte) (cipher.Stream, error) {
	if len(key) < 15 || len(checksum) < 32 {
		return nil, errors.New("invalid size of key or checksum")
	}

	k := make([]byte, 32)

	copy(k, key[:16])
	copy(k, checksum[16:32])

	iv := []byte{
		checksum[0], checksum[1], checksum[2], checksum[3], key[20], key[21], key[22], key[23],
		key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31],
	}

	ctr, err := NewCipherCtr(k, iv)
	if err != nil {
		return nil, err
	}

	return ctr, nil
}

func NewCipherCtr(key, iv []byte) (cipher.Stream, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewCTR(c, iv), nil
}
