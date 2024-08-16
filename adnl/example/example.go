package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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

	tlHandler := tl.New()

	node := cfg.Dht.StaticNodes.Nodes[0]

	ipDec := node.AddrList.Addrs[0].IP
	port := node.AddrList.Addrs[0].Port
	key := node.ID.Key

	dhtNodeKey, err := base64.RawStdEncoding.DecodeString(key)
	if err != nil {
		log.Fatal(err)
	}

	// convert decimal ip to normal ip formatting
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, uint32(ipDec))

	// shout to this IP and PORT using UDP
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// adnl.message.createChannel key:int256 date:int = adnl.Message;
	channelKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	date := time.Now().Unix()
	createChn := adnl.CreateChannel{
		Key:  channelKey,
		Date: date,
	}

	queryID := make([]byte, 32)
	rand.Read(queryID)

	query, err := tlHandler.Serialize(adnl.GetSignedAddressList{}, true)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("GET SIGNED ADDRESS LIST QUERY: ", hex.EncodeToString(query))

	msgQuery := adnl.Query{
		QueryID: queryID,
		Query:   query,
	}

	ourPub, ourPk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	buff := make([]byte, 30)
	rand.Read(buff)
	rand1, rand2 := buff[:15], buff[15:]

	pkt := adnl.PacketContent{
		Rand1: rand1,
		Flags: 0x05d9,
		From: adnl.PublicKeyED25519{
			Key: ourPub,
		},
		Messages: []any{
			createChn,
			msgQuery,
		},
		AddressList: adnl.List{
			Addresses:  []adnl.UDP{},
			Version:    date,
			ReinitDate: date,
			Priority:   0,
			ExpireAt:   0,
		},
		Seqno:               1,
		ConfirmSeqno:        0,
		RecvAddrListVersion: date,
		ReinitDate:          date,
		DstReinitDate:       0,
		Rand2:               rand2,
	}

	models := []tl.ModelRegister{
		{T: adnl.CreateChannel{}, Def: adnl.TLCreateChannel},
		{T: adnl.GetSignedAddressList{}, Def: adnl.TLSignedAddressList},
		{T: adnl.PublicKeyED25519{}, Def: adnl.TLPublicKeyEd25519},
		{T: adnl.Query{}, Def: adnl.TLMessageQuery},
		{T: adnl.UDP{}, Def: adnl.TLAddressUDP},
		{T: adnl.List{}, Def: adnl.TLAddressList},
	}
	tlHandler.Register(models)

	data, err := tlHandler.Serialize(pkt, true)
	if err != nil {
		log.Fatal(err)
	}

	pkt.Signature = ed25519.Sign(ourPk, data)
	// serialize again, this time with signature included
	// so we need to enable the 11th bit on flag which
	pkt.Flags = 0x0dd9

	data, err = tlHandler.Serialize(pkt, true)
	if err != nil {
		log.Fatal(err)
	}

	h := sha256.Sum256(data)

}
