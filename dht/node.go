package dht

import (
	"encoding/hex"
	"log"
	"math/big"
	"net"
	"os"

	"github.com/xssnick/tonutils-go/tl"
)

var (
	PingID      = TLID("dht.ping random_id:long = dht.Pong")
	PongID      = TLID("dht.pong random_id:long = dht.Pong")
	StoreID     = TLID("dht.store value:dht.value = dht.Stored")
	FindNodeID  = TLID("dht.findNode key:int256 k:int = dht.Nodes")
	FindValueID = TLID("dht.findValue key:int256 k:int = dht.ValueResult")
)

type adnl interface {
	Send(dst *Node, data []byte)
	// Receive return a channel of data that is assumed to be
	// a structure serialized with TL, including 4-byte prefix(a boxed scheme)
	// indicating the scheme ID
	Receive() <-chan []byte
}

type storage interface {
	Get(key *big.Int) ([]byte, error)
	Set(key *big.Int, value []byte) error
}

type bucket []*nodeDescription

type nodeDescription struct {
	// ip address of the node
	ip net.IP
	// port of node
	port int
	// "semi permanent" address of the node or dht address
	semiPermanentAddress *big.Int
	// last ping timestamp
	lastPingTs int64
	// delay in seconds of the latest ping response
	delay int64
}

type Node struct {
	// values table stores key-values in the distributed hash table(dht)
	// using temporary storage just for demonstration
	table storage

	// routing table, i-th bucket contains known nodes that lie
	// at a Kademlia distance from 2*i to 2**(i+1) - 1, from the node address
	// "best" nodes should be first, defining by "best" those which round trip delay is smaller
	routeTable [256]*bucket

	// TON DHT uses ADNL as the transport layer to communicate between nodes
	adnl adnl

	// ip address of the node
	ip net.IP
	// port of node
	port int
	// "semi permanent" address of the node or dht address
	semiPermanentAddress *big.Int

	logger *log.Logger
}

// New initialize a new node
func New() *Node {
	logger := log.New(os.Stdout, "[dht-node]", log.Lshortfile)
	return &Node{
		logger: logger,
	}
}

// Run node listenning on incomming requests from other peers in the network.
func (n *Node) Run() {
	// listen on port

	// dipatch boot
	n.boot()

	errChn := make(chan error, 1)
	// process errors
	go func(<-chan error) {

		for err := range errChn {
			n.logger.Printf("error: %s", err)
		}

	}(errChn)

	// listen on incomming messages
	for data := range n.adnl.Receive() {
		go n.handleCMD(data, errChn)
	}
}

func (n *Node) handleCMD(data []byte, errChn chan<- error) {
	if len(data) < 4 {
		return
	}

	// read first four bytes from data to identify command scheme ID
	cmdID := hex.EncodeToString(data[:4])
	switch cmdID {
	case PingID:
		// parse ping command
		pcmd := Ping{}
		_, err := tl.Parse(&pcmd, data, true)
		if err != nil {
			errChn <- err
			return
		}

		// respond with received id
	case PongID:
	case FindNodeID:
	case FindValueID:
	case StoreID:
	default:
		// unknown method
		return
	}
}

// boot populates node routing table by looking up it's own address.
// Identifying in this process the s nearest nodes to itself. Downloading
// from them the key-value they store.
func (n *Node) boot() {}

// SendPing performs a PING command to a given node.
func (n *Node) SendPing(dst *Node) {
	data := make([]byte, 0)
	// send ping command to dst
	n.adnl.Send(dst, data)
}

// SendPong sends a PONG response to dst.
func (n *Node) SendPong(dst *Node) {
	data := make([]byte, 0)
	// send ping command to dst
	n.adnl.Send(dst, data)
}

// SendStore send STORE command to dst key-value on value table.
func (n *Node) SendStore(dst *Node, key *big.Int, val []byte) {
	data := make([]byte, 0)
	// send ping command to dst
	n.adnl.Send(dst, data)
}

// SendFindNode asks the node to return l Kademlia-nearest
// known nodes (from its Kademlia routing table) to key.
func (n *Node) SendFindNode(dst *Node, key *big.Int, l int) {
	data := make([]byte, 0)
	// send ping command to dst
	n.adnl.Send(dst, data)
}

// SendFindValue asks dst for value of key, in case dst doesn't knows
// dst will ask to its known nodes.
func (n *Node) SendFindValue(dst *Node, key *big.Int) {
	data := make([]byte, 0)
	// send ping command to dst
	n.adnl.Send(dst, data)
}

// ReceivePing handle PING command from src node.
func (n *Node) ReceivePing(src *Node) {
	// parse ping
}

// ReceiveStore handle incomming STORE key-value on value table.
func (n *Node) ReceiveStore(key *big.Int, val []byte) {}

// ReceiveFindNode handle FIND_NODE command.
func (n *Node) ReceiveFindNode(dst *Node, key *big.Int, l int) {}

// ReceiveFindValue handle FIND_VALUE command.
func (n *Node) ReceiveFindValue(dst *Node, key *big.Int) {}
