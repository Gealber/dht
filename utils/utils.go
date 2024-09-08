package utils

import (
	crrand "crypto/rand"
	"math/rand"
)

// RandomBuff generate two random buffers following the weird way done in ton blockchain implementation
// https://github.com/ton-blockchain/ton/blob/0c21ce2ee46f5b84c80f0622f79161442642798a/adnl/adnl-packet.cpp#L126
func RandomBuff() ([]byte, []byte) {
	r1Size, r2Size := 15, 15
	r1Uint := rand.Uint32()
	if r1Uint&1 == 1 {
		r1Size = 7
	}

	r2Uint := rand.Uint32()
	if r2Uint&1 == 1 {
		r2Size = 7
	}

	r1 := make([]byte, r1Size)
	r2 := make([]byte, r2Size)
	crrand.Read(r1)
	crrand.Read(r2)

	return r1, r2
}
