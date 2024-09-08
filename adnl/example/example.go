package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Gealber/dht/tl"
	"github.com/Gealber/dht/utils"
	xssnickadnl "github.com/xssnick/tonutils-go/adnl"
)

func main() {
	done := make(chan struct{})
	errChn := make(chan error, 1)
	aPub, aPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("SRV PUB: %x\n", aPub)

	go func() {
		errChn <- server(aPub, aPriv, done)
	}()

	// running adnl server in background
	err = example(aPub, 2130706433, 9055)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	select {
	case err := <-errChn:
		log.Fatal(err)
	case <-ctx.Done():
		log.Println("sending done signal")
		done <- struct{}{}
	}
}

func example(dhtNodeKey []byte, ipDec, port int) error {
	ourPub, ourPk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// cfg, err := config.LoadConfig()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// node := cfg.Dht.StaticNodes.Nodes[0]

	// ipDec := node.AddrList.Addrs[0].IP
	// port := node.AddrList.Addrs[0].Port
	// key := node.ID.Key

	// dhtNodeKey, err := base64.StdEncoding.DecodeString(key)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// convert decimal ip to normal ip formatting
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(ipDec))
	log.Println("IP: ", ip.String())

	// shout to this IP and PORT using UDP
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", ip.String(), int32(port)))
	if err != nil {
		return err
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

	payload, err := buildExamplePayload(dhtNodeKey, ourPub, ourPk)
	if err != nil {
		log.Fatal(err)
	}

	// ignores for the sake of the example the amount of data written
	written, err := conn.Write(payload)
	if err != nil {
		return err
	}

	log.Println("WRITTEN AMOUNT OF BYTES: ", written, "from: ", len(payload))

	// wait for 5 secs before shutting down
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
	}

	return nil
}

func buildExamplePayload(dhtNodeKey []byte, ourPub ed25519.PublicKey, ourPk ed25519.PrivateKey) ([]byte, error) {
	tlHandler := tl.New()

	// register models in order to perform a TL serialization
	models := []tl.ModelRegister{
		{T: tl.AdnlPacketContent{}, Def: tl.TLPacketContents},
		{T: tl.AdnlMessageCreateChannel{}, Def: tl.TLCreateChannel},
		{T: tl.GetSignedAddressList{}, Def: tl.TLSignedAddressList},
		{T: tl.PublicKeyED25519{}, Def: tl.TLPublicKeyEd25519},
		{T: tl.Query{}, Def: tl.TLMessageQuery},
		{T: tl.AdnlAddressUDP{}, Def: tl.TLAddressUDP},
		{T: tl.AdnlAddressList{}, Def: tl.TLAddressList},
		{T: tl.Ping{}, Def: tl.TLPing},
	}
	tlHandler.Register(models)

	channelKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// adnl.message.createChannel key:int256 date:int = adnl.Message;
	date := time.Now().Unix()
	createChn := tl.AdnlMessageCreateChannel{
		Key:  channelKey,
		Date: date,
	}

	query, err := tlHandler.Serialize(tl.Ping{
		Value: 1,
	}, true)
	if err != nil {
		return nil, err
	}

	queryID := make([]byte, 32)
	rand.Read(queryID)

	msgQuery := tl.Query{
		QueryID: queryID,
		Query:   query,
	}

	buff := make([]byte, 30)
	rand.Read(buff)
	rand1, rand2 := buff[:15], buff[15:]

	pkt := tl.AdnlPacketContent{
		Rand1: rand1,
		Flags: 0x05d9,
		From: tl.PublicKeyED25519{
			Key: ourPub,
		},
		Messages: []any{
			createChn,
			msgQuery,
		},
		AddressList: tl.AdnlAddressList{
			Addresses:  []tl.AdnlAddressUDP{},
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

	checkSum := sha256.Sum256(data)

	sharedKey, err := utils.GenerateSharedKey(ourPk, dhtNodeKey)
	if err != nil {
		return nil, err
	}

	sharedCipher, err := utils.BuildSharedCipher(sharedKey, checkSum[:])
	if err != nil {
		return nil, err
	}

	sharedCipher.XORKeyStream(data, data)

	keyID, err := utils.KeyIDEd25519(dhtNodeKey)
	if err != nil {
		return nil, err
	}

	pLen := len(keyID) + len(ourPub) + len(checkSum) + len(data)
	// | SERVER KEY ID | OUR PUB KEY | SHA256 CONTENT HASH BEFORE ENCRYPTION | ENCRYPTED CONTENT OF THE PACKET |
	payload := make([]byte, pLen)
	copy(payload, keyID)
	copy(payload[32:], ourPub)
	copy(payload[64:], checkSum[:])
	copy(payload[96:], data)

	return payload, nil
}

type TestMsg struct {
	Data []byte `tl:"bytes"`
}

func server(aPub ed25519.PublicKey, aPriv ed25519.PrivateKey, done chan struct{}) error {
	a := xssnickadnl.NewGateway(aPriv)
	err := a.StartServer("127.0.0.1:9055")
	if err != nil {
		return err
	}
	a.SetConnectionHandler(connHandler)

	fmt.Println("Listening on 127.0.0.1:9055 and waiting for context to timeout")
	select {
	case <-done:
	}

	return nil
}

func connHandler(client xssnickadnl.Peer) error {
	client.SetQueryHandler(func(msg *xssnickadnl.MessageQuery) error {
		switch m := msg.Data.(type) {
		case xssnickadnl.MessagePing:
			err := client.Answer(context.Background(), msg.ID, xssnickadnl.MessagePong{
				Value: m.Value,
			})
			if err != nil {
				panic(err)
			}
		}
		return nil
	})
	client.SetCustomMessageHandler(func(msg *xssnickadnl.MessageCustom) error {
		return client.SendCustomMessage(context.Background(), TestMsg{Data: make([]byte, 1280)})
	})
	client.SetDisconnectHandler(func(addr string, key ed25519.PublicKey) {
	})
	return nil
}
