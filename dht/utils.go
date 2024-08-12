package dht

import (
	"math/big"
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
