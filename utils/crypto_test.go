package utils

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/xssnick/tonutils-go/adnl"
)

// TODO: these tests should be replaced by tests that doesn't rely on correctness of tonutils-go implementation
// but will for later, I don't understand quite well how to test this
func TestGenerateSharedKey(t *testing.T) {
	_, ourPk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sharedKey, err := GenerateSharedKey(ourPk, serverPub)
	if err != nil {
		t.Fatal(err)
	}

	// let's use tonutils-go implementation as our source of truth
	tonutilsSharedKey, err := adnl.SharedKey(ourPk, serverPub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sharedKey, tonutilsSharedKey) {
		t.Fatal("bytes differs")
	}
}

func TestBuildShareCipher(t *testing.T) {
	_, ourPk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sharedSecret, err := GenerateSharedKey(ourPk, serverPub)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 100)
	rand.Read(data)

	checkSum := sha256.Sum256(data)

	cipher, err := BuildSharedCipher(sharedSecret, checkSum[:])
	if err != nil {
		t.Fatal(err)
	}

	tonutilsCipher, err := BuildSharedCipher(sharedSecret, checkSum[:])
	if err != nil {
		t.Fatal(err)
	}

	dataToExcrypt := make([]byte, 100)
	rand.Read(dataToExcrypt)

	got := make([]byte, 100)
	want := make([]byte, 100)

	cipher.XORKeyStream(got, dataToExcrypt)
	tonutilsCipher.XORKeyStream(want, dataToExcrypt)

	if !bytes.Equal(want, got) {
		t.Fatal("ciphered data differs")
	}
}
