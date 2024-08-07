package dht

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"math/big"
	"strings"
)

func KademliaDistance(x, y *big.Int) *big.Int {
	return new(big.Int).Xor(x, y)
}

// TLID given an TL-scheme computes the TL-ID
// returning the hex representation of it.
func TLID(scheme string) string {
	scheme = strings.ReplaceAll(scheme, "(", "")
	scheme = strings.ReplaceAll(scheme, ")", "")
	scheme = strings.ReplaceAll(scheme, ";", "")

	id := crc32.ChecksumIEEE([]byte(scheme))
	b := make([]byte, 4)

	binary.LittleEndian.PutUint32(b, id)

	return hex.EncodeToString(b)
}
