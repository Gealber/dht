package dht

import (
	"math/big"
)

// The TL definitions used here can be found in the TON blockchain repository
// https://github.com/ton-blockchain/ton/blob/master/tl/generate/scheme/ton_api.tl
// The one used are defined in dht/dht.tl

// Ping scheme
// TL definition: dht.ping random_id:long = dht.Pong
type Ping struct {
	ID int64 `tl:"long"`
}

// Pong scheme
// TL definition: dht.pong random_id:long = dht.Pong
type Pong struct {
	ID int64 `tl:"long"`
}

type Key struct {
	ID   *big.Int `tl:"int256"`
	Name []byte   `tl:"bytes"`
	Idx  int      `tl:"int"`
}

// KeyDescription describes the "type" of object being stored
// refer to 3.2.9 on TON whitepaper.
type KeyDescription struct {
	ID         PublicKeyED25519 `tl:"PublicKey"`
	Key        Key              `tl:"dht.key"`
	UpdateRule any              `tl:"dht.UpdateRule"`
	Signature  []byte           `tl:"bytes"`
}

// Value value to be stored
type Value struct {
	Key       KeyDescription `tl:"dht.keyDescription"`
	Values    []byte         `tl:"bytes"`
	TLL       int            `tl:"int"`
	Signature []byte         `tl:"bytes"`
}

// Store scheme
// TL definition: dht.store value:dht.value = dht.Stored
type Store struct {
	Value Value `tl:"dht.Value"`
}

// FindNode
// TL definition: dht.findNode key:int256 k:int = dht.Nodes;
// Object used to asks the node to return k Kademlia-nearest
// known nodes (from its Kademlia routing table) to key
type FindNode struct {
	Key *big.Int `tl:"int256"`
	K   int      `tl:"int"`
}

type FindValue struct {
	Key *big.Int `tl:"int256"`
	K   int      `tl:"int"`
}

type PrivateKeyAES struct {
	Key *big.Int `tl:"int256"`
}

type PublicKeyED25519 struct {
	Keyy *big.Int `tl:"int256"`
}

type PublicKeyAES struct {
	Key *big.Int `tl:"int256"`
}

type Overlay struct {
	Name []byte `tl:"bytes"`
}
