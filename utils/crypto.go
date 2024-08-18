package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

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

func GenerateSharedKey(ourPk ed25519.PrivateKey, serverPb ed25519.PublicKey) ([]byte, error) {
	pkPriv := ed25519.PrivateKey(ourPk)
	xPriv := ed25519PrivateKeyToCurve25519(pkPriv)

	xPub, err := ed25519PublicKeyToCurve25519(serverPb)
	if err != nil {
		return nil, err
	}

	secret, err := curve25519.X25519(xPriv, xPub)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// ed25519PrivateKeyToCurve25519 converts a ed25519 private key in X25519 equivalent
// source: https://github.com/FiloSottile/age/blob/980763a16e30ea5c285c271344d2202fcb18c33b/agessh/agessh.go#L287
func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

// ed25519PublicKeyToCurve25519 converts a ed25519 public key in X25519 equivalent
// source: https://github.com/FiloSottile/age/blob/main/agessh/agessh.go#L190
func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}
