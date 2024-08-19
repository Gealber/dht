package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Gealber/dht/adnl"
	"github.com/Gealber/dht/config"
	"github.com/Gealber/dht/tl"
	"github.com/Gealber/dht/utils"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	node := cfg.Dht.StaticNodes.Nodes[0]

	ipDec := node.AddrList.Addrs[0].IP
	port := node.AddrList.Addrs[0].Port
	key := node.ID.Key

	dhtNodeKey, err := base64.StdEncoding.DecodeString(key)
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
	// setting a timeout for reads
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// run read loop in background, buffer read size 4KB
	buff := make([]byte, 4096)
	go func() {
		for {
			log.Println("Reading data...")
			n, err := conn.Read(buff)
			if err != nil {
				if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "i/o timeout") {
					return
				}

				log.Println("ERROR WHILE READING: ", err)
				return
			}

			log.Println(hex.EncodeToString(buff[:n]))
		}
	}()

	payload, err := buildExamplePayload(dhtNodeKey)
	if err != nil {
		log.Fatal(err)
	}

	// ignores for the sake of the example the amount of data written
	_, err = conn.Write(payload)
	if err != nil {
		log.Fatal(err)
	}

	// wait for 5 secs before shutting down
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
	}
}

func buildExamplePayload(dhtNodeKey []byte) ([]byte, error) {
	tlHandler := tl.New()

	models := []tl.ModelRegister{
		{T: adnl.PacketContent{}, Def: adnl.TLPacketContents},
		{T: adnl.CreateChannel{}, Def: adnl.TLCreateChannel},
		{T: adnl.GetSignedAddressList{}, Def: adnl.TLSignedAddressList},
		{T: adnl.PublicKeyED25519{}, Def: adnl.TLPublicKeyEd25519},
		{T: adnl.Query{}, Def: adnl.TLMessageQuery},
		{T: adnl.UDP{}, Def: adnl.TLAddressUDP},
		{T: adnl.List{}, Def: adnl.TLAddressList},
	}
	tlHandler.Register(models)

	// adnl.message.createChannel key:int256 date:int = adnl.Message;
	channelKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	msgQuery := adnl.Query{
		QueryID: queryID,
		Query:   query,
	}

	ourPub, ourPk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
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

	data, err := tlHandler.Serialize(pkt, true)
	if err != nil {
		return nil, err
	}

	pkt.Signature = ed25519.Sign(ourPk, data)
	// serialize again, this time with signature included
	// so we need to enable the 11th bit on flag which
	pkt.Flags = 0x0dd9

	data, err = tlHandler.Serialize(pkt, true)
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(data)

	sharedKey, err := utils.GenerateSharedKey(ourPk, dhtNodeKey)
	if err != nil {
		return nil, err
	}

	sharedCipher, err := utils.BuildSharedCipher(sharedKey, h[:])
	if err != nil {
		return nil, err
	}

	sharedCipher.XORKeyStream(data, data)

	keyID, err := utils.KeyIDEd25519(dhtNodeKey)
	if err != nil {
		return nil, err
	}

	log.Println("DATA ENCRYPTED LENGTH: ", len(data))
	pLen := len(keyID) + len(ourPub) + len(h) + len(data)
	log.Println("PAYLOAD LENGTH: ", pLen)
	// | SERVER KEY ID | OUR PUB KEY | SHA256 CONTENT HASH BEFORE ENCRYPTION | ENCRYPTED CONTENT OF THE PACKET |
	payload := make([]byte, pLen)
	copy(payload, keyID)
	copy(payload[32:], ourPub)
	copy(payload[64:], h[:])
	copy(payload[96:], data)

	return payload, nil
}
