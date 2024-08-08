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

// DistanceIdx given a distance d, find i such as 2**i <= d <= 2**(i+1)-1
func DistanceIdx(d *big.Int) int {
	i := 0
	p := big.NewInt(1)

	for p.Cmp(d) < 0 {
		p.Lsh(p, 1)
		i++
	}

	if i >= 256 {
		return 255
	}

	return i
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
