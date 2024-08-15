package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Gealber/dht/adnl"
	"github.com/Gealber/dht/config"
	"github.com/Gealber/dht/tl"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	node := cfg.Dht.StaticNodes.Nodes[0]

	ipDec := node.AddrList.Addrs[0].IP
	port := node.AddrList.Addrs[0].Port
	// key := node.ID.Key

	// keyB, err := base64.RawStdEncoding.DecodeString(key)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// convert decimal ip to normal ip formatting
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, uint32(ipDec))

	// shout to this IP and PORT using UDP
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// first let's send create-channel
	// adnl.message.createChannel key:int256 date:int = adnl.Message;
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	msgCreateChannel := adnl.CreateChannel{
		Key:  pub,
		Date: time.Now().Unix(),
	}

	tlHandler := tl.New()

	createChannelData, err := tlHandler.Serialize(msgCreateChannel, true)
	if err != nil {
		log.Fatal(err)
	}

	// // sending create channel request
	// n, err := conn.Write(createChannelData)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// log.Printf("written %d byte\n", n)
	log.Printf("%x", createChannelData)

	// second message will be the actual query
	// serialize GetSignedAddressList
	var addrList adnl.GetSignedAddressList

	query, err := tlHandler.Serialize(addrList, true)
	if err != nil {
		log.Fatal(err)
	}

	// adnl.message.query query_id:int256 query:bytes = adnl.Message
	queryID := make([]byte, 32)
	rand.Read(queryID)
	adnlQuery := adnl.Query{
		QueryID: queryID,
		Query:   query,
	}

	msgQueryData, err := tlHandler.Serialize(adnlQuery, true)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%x", msgQueryData)

	// building packet
	r1 := make([]byte, 15)
	rand.Read(r1)
	r2 := make([]byte, 15)
	rand.Read(r2)
	log.Printf("RAND1: %x\n", r1)
	log.Printf("RAND2: %x\n", r2)

	var seqno int64 = 1
	var confirmSeqno int64 = 0
	tm := int32(time.Now().Unix())

	packet := adnl.PacketContent{
		Rand1: r1,
		Flags: 0xd9050000,
		From: adnl.PublicKeyED25519{
			Key: pub,
		},
		Messages: []any{msgCreateChannel, msgQueryData},
		Address: &adnl.List{
			Addresses:  []*adnl.UDP{},
			Version:    tm,
			ReinitDate: tm,
		},
		Seqno:               &seqno,
		ConfirmSeqno:        &confirmSeqno,
		RecvAddrListVersion: &tm,
		ReinitDate:          &tm,
		Rand2:               r2,
	}

	pktData, err := tlHandler.Serialize(packet, true)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%x", pktData)
}
