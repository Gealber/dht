package dht

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	gealberTL "github.com/Gealber/dht/tl"
	"github.com/xssnick/tonutils-go/tl"
)

var (
	PingID      = gealberTL.SchemeID("dht.ping random_id:long = dht.Pong")
	PongID      = gealberTL.SchemeID("dht.pong random_id:long = dht.Pong")
	StoreID     = gealberTL.SchemeID("dht.store value:dht.value = dht.Stored")
	FindNodeID  = gealberTL.SchemeID("dht.findNode key:int256 k:int = dht.Nodes")
	FindValueID = gealberTL.SchemeID("dht.findValue key:int256 k:int = dht.ValueResult")
)

type adnlMsg struct {
	src  *Node
	data []byte
}

type adnl interface {
	Send(dst *Node, data []byte)
	// Receive return a channel of data that is assumed to be
	// a structure serialized with TL, including 4-byte prefix(a boxed scheme)
	// indicating the scheme ID
	Receive() <-chan adnlMsg
}

type storage interface {
	Get(key *big.Int) ([]byte, bool)
	Set(key *big.Int, value []byte) error
}

type bucket []*nodeDescription

type nodeDescription struct {
	id PublicKeyED25519
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

func (nd *nodeDescription) ToNode() *Node {
	return &Node{
		id:                   nd.id,
		ip:                   nd.ip,
		port:                 nd.port,
		semiPermanentAddress: nd.semiPermanentAddress,
	}
}

type Node struct {
	id PublicKeyED25519
	// values table stores key-values in the distributed hash table(dht)
	// using temporary storage just for demonstration
	table storage

	// routing table, i-th bucket contains known nodes that lie
	// at a Kademlia distance from 2*i to 2**(i+1) - 1, from the node address
	// "best" nodes should be first, defining by "best" those which round trip delay is smaller
	routeTable [256]bucket

	// TON DHT uses ADNL as the transport layer to communicate between nodes
	adnl adnl

	// ip address of the node
	ip net.IP
	// port of node
	port int
	// "semi permanent" address of the node or dht address
	semiPermanentAddress *big.Int

	logger *log.Logger
	// availabilityTracker tracks the PING/PONG response delays with other nodes
	// storing id:timestamp
	availabilityTracker map[int64]int64
	// idxMap keeps track of node.id:idx in routing table, to avoid re-computing this index
	idxMap map[*big.Int]int

	mu sync.Mutex
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
			if err != nil {
				n.logger.Printf("error: %s\n", err)
			}
		}

	}(errChn)

	// listen on incomming messages
	for data := range n.adnl.Receive() {
		go n.handleReceivedCMD(data, errChn)
	}
}

func (n *Node) handleReceivedCMD(msg adnlMsg, errChn chan<- error) {
	if len(msg.data) < 4 {
		return
	}

	// read first four bytes from data to identify command scheme ID
	cmdID := hex.EncodeToString(msg.data[:4])
	switch cmdID {
	case PingID:
		errChn <- n.ReceivePing(msg.src, msg.data)
	case PongID:
		errChn <- n.ReceivePong(msg.src, msg.data)
	case FindNodeID:
		errChn <- n.ReceiveFindNode(msg.src, msg.data)
	case FindValueID:
		errChn <- n.ReceiveFindValue(msg.src, msg.data)
	case StoreID:
		errChn <- n.ReceiveStore(msg.src, msg.data)
	default:
		errChn <- fmt.Errorf("unknown cmd received with data: %x", msg.data)
	}
}

// boot populates node routing table by looking up it's own address.
// Identifying in this process the s nearest nodes to itself. Downloading
// from them the key-value they store.
func (n *Node) boot() {}

// SendPing performs a PING command to a given node.
func (n *Node) SendPing(dst *Node) error {
	id, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	ping := Ping{
		ID: id.Int64(),
	}
	data, err := tl.Serialize(&ping, true)
	if err != nil {
		return err
	}

	// send ping command to dst
	go n.adnl.Send(dst, data)

	n.mu.Lock()
	defer n.mu.Unlock()

	// save availability tracker
	ts := time.Now().Unix()
	n.availabilityTracker[id.Int64()] = ts
	// update lastPingTs in route table
	n.updateNodeLastPingTs(dst, ts)

	return nil
}

// SendPong sends a PONG response to dst.
func (n *Node) SendPong(dst *Node, id int64) error {
	pong := Pong{
		ID: id,
	}
	respData, err := tl.Serialize(&pong, true)
	if err != nil {
		return err
	}

	// respond with received id
	n.adnl.Send(dst, respData)

	return nil
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
func (n *Node) ReceivePing(src *Node, data []byte) error {
	// parse ping command
	var cmd Ping
	_, err := tl.Parse(&cmd, data, true)
	if err != nil {
		return err
	}

	return n.SendPong(src, cmd.ID)
}

// ReceivePong handle PONG response from src node.
func (n *Node) ReceivePong(src *Node, data []byte) error {
	// parse pong command
	var cmd Pong
	_, err := tl.Parse(&cmd, data, true)
	if err != nil {
		return err
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// update availability track of nodes
	lastTs := n.availabilityTracker[cmd.ID]
	delay := time.Now().Unix() - lastTs
	delete(n.availabilityTracker, cmd.ID)
	n.updateNodeDelay(src, delay)

	return nil
}

// ReceiveStore handle incomming STORE key-value on value table.
func (n *Node) ReceiveStore(src *Node, data []byte) error {
	// parse STORE command
	var cmd Store
	_, err := tl.Parse(&cmd, data, true)
	if err != nil {
		return err
	}

	// TODO: implement receive STORE mechanism
	return nil
}

// ReceiveFindNode handle FIND_NODE command.
func (n *Node) ReceiveFindNode(src *Node, data []byte) error {
	// parse FindNode command
	var cmd FindNode
	_, err := tl.Parse(&cmd, data, true)
	if err != nil {
		return err
	}

	// TODO: implement receive FIND_NODE mechanism
	return nil
}

// ReceiveFindValue handle FIND_VALUE command.
func (n *Node) ReceiveFindValue(src *Node, data []byte) error {
	// parse FindValue command
	var cmd FindValue
	_, err := tl.Parse(&cmd, data, true)
	if err != nil {
		return err
	}

	// TODO: implement FIND_VALUE mechanism
	// look find value in our storage
	value, ok := n.table.Get(cmd.Key)
	if !ok {
		// pass request to nearest K nodes
		nearestNodes := n.selectKNearestNodes(cmd.Key, cmd.K)
		// send this nodes to src
		v := ValueResult{
			Nodes: nearestNodes,
		}

		// TODO: check if this model should be boxed
		d, err := tl.Serialize(&v, false)
		if err != nil {
			return err
		}

		go n.adnl.Send(src, d)

		return nil
	}

	res := ValueResult{
		Value: &Value{
			Values: value,
		},
	}

	resData, err := tl.Serialize(&res, false)
	if err != nil {
		return err
	}

	n.adnl.Send(src, resData)

	return nil
}

// updateNodeDelay given a known node m, update its delay information in the routing table.
// should be used with a write mutex
func (n *Node) updateNodeDelay(m *Node, delay int64) {
	idx, bIdx := n.findNodeInRouteTable(m)
	if idx == -1 || bIdx == -1 {
		return
	}

	n.routeTable[idx][bIdx].delay = delay
	// if the new delay is "best" than previous elements in bucket
	// then should be replace in the right position
	// re-sorting the bucket according to their delays
	sort.Slice(n.routeTable[idx], func(i, j int) bool {
		return n.routeTable[idx][i].delay < n.routeTable[idx][j].delay
	})
}

// updateNodeLastPingTs given a known node m, update its delay information in the routing table.
// should be used with a mutex
func (n *Node) updateNodeLastPingTs(m *Node, lastTs int64) {
	idx, bIdx := n.findNodeInRouteTable(m)
	if idx == -1 || bIdx == -1 {
		return
	}

	n.routeTable[idx][bIdx].lastPingTs = lastTs
}

// findNodeInRouteTable finds a node m, routeTable index and bucket index.
func (n *Node) findNodeInRouteTable(m *Node) (int, int) {
	idx, ok := n.idxMap[m.id.Key]
	if !ok {
		d := KademliaDistance(n.id.Key, m.id.Key)
		idx = DistanceIdx(d)
	}

	b := n.routeTable[idx]
	// find node in bucket to update the delay,
	// using binary search for finding this node
	// bucket b needs to be sorted
	bIdx := sort.Search(len(b), func(i int) bool {
		return b[i].id.Key.Cmp(m.id.Key) == 0
	})

	return idx, bIdx
}

// selectKNearestNodes select from known nodes the k nearest nodes
// to Key
func (n *Node) selectKNearestNodes(Key *big.Int, k int) []*Node {
	knownNodes := make([]*Node, 0)
	for _, b := range n.routeTable {
		for _, nd := range b {
			knownNodes = append(knownNodes, nd.ToNode())
		}
	}

	// sort nodes according to nearest to Key
	sort.Slice(knownNodes, func(i, j int) bool {
		di := KademliaDistance(knownNodes[i].id.Key, Key)
		dj := KademliaDistance(knownNodes[j].id.Key, Key)

		return di.Cmp(dj) < 0
	})

	return knownNodes[:k]
}
