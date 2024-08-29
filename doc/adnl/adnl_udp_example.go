package adnl

import (
	"crypto/aes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Gealber/dht/adnl"
	"github.com/Gealber/dht/tl"
	"github.com/Gealber/dht/utils"
)

type Peer struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PublicKey
}

type Channel struct {
	outEncrKey []byte
	inDecrKey  []byte
}

func main() {}

// sender implements a simple peer that will
// 1. Create a channel
// 2. Send 10 ping commands
func sender(pub ed25519.PublicKey, priv ed25519.PrivateKey, peerPub ed25519.PublicKey) error {
	// we will be listening to all incomming connections
	// on port 3278 port
	conn, err := net.Dial("udp", ":3279")
	if err != nil {
		return err
	}
	defer conn.Close()
	// setting a timeout for reads
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	go func() {
		// listen to incomming connections
		buff := make([]byte, 4096)

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

			log.Println("PACKET RECEIVED", hex.EncodeToString(buff[:n]))
		}
	}()

	// write a ping command
	pkt, err := firstPkt(pub, priv, peerPub)
	if err != nil {
		return err
	}

	_, err = conn.Write(pkt)
	if err != nil {
		return err
	}

	return nil
}

// receiver just implement a simple peer that will:
// 1. Confirm channel
// 2. Respond to each ping command with a pong
func receiver(pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	// we will be listening to all incomming connections
	// on port 3278 port
	conn, err := net.Dial("udp", ":3278")
	if err != nil {
		return err
	}
	defer conn.Close()
	// setting a timeout for reads
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// listen to incomming connections
	buff := make([]byte, 4096)

	for {
		log.Println("Reading data...")
		n, err := conn.Read(buff)
		if err != nil {
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "i/o timeout") {
				return nil
			}

			log.Println("ERROR WHILE READING: ", err)
			return err
		}

		log.Println("PACKET RECEIVED", hex.EncodeToString(buff[:n]))
	}
}

// firstPkt first packet to initi channel
func firstPkt(pub ed25519.PublicKey, priv ed25519.PrivateKey, peerPub ed25519.PublicKey) ([]byte, error) {
	tlH := tl.New()
	tlH.Register([]tl.ModelRegister{
		{T: adnl.PacketContent{}, Def: adnl.TLPacketContents},
		{T: adnl.CreateChannel{}, Def: adnl.TLCreateChannel},
		{T: adnl.PublicKeyED25519{}, Def: adnl.TLPublicKeyEd25519},
		{T: adnl.Query{}, Def: adnl.TLMessageQuery},
		{T: adnl.UDP{}, Def: adnl.TLAddressUDP},
		{T: adnl.Ping{}, Def: adnl.TLPing},
	})

	channelKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// adnl.message.createChannel key:int256 date:int = adnl.Message;
	date := time.Now().Unix()
	createChn := adnl.CreateChannel{
		Key:  channelKey,
		Date: date,
	}

	buff := make([]byte, 30)
	rand.Read(buff)
	rand1, rand2 := buff[:15], buff[15:]

	pkt := adnl.PacketContent{
		Rand1: rand1,
		Flags: 0x05d9,
		From: adnl.PublicKeyED25519{
			Key: pub,
		},
		Message: createChn,
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

	data, err := tlH.Serialize(pkt, true)
	if err != nil {
		return nil, err
	}

	pkt.Signature = ed25519.Sign(priv, data)
	// serialize again, this time with signature included
	// so we need to enable the 11th bit on flag which
	pkt.Flags = 0x0dd9

	data, err = tlH.Serialize(pkt, true)
	if err != nil {
		return nil, err
	}

	checkSum := sha256.Sum256(data)

	sharedKey, err := utils.GenerateSharedKey(priv, peerPub)
	if err != nil {
		return nil, err
	}

	sharedCipher, err := utils.BuildSharedCipher(sharedKey, checkSum[:])
	if err != nil {
		return nil, err
	}

	sharedCipher.XORKeyStream(data, data)

	keyID, err := utils.KeyIDEd25519(peerPub)
	if err != nil {
		return nil, err
	}

	pLen := len(keyID) + len(peerPub) + len(checkSum) + len(data)
	// | SERVER KEY ID | OUR PUB KEY | SHA256 CONTENT HASH BEFORE ENCRYPTION | ENCRYPTED CONTENT OF THE PACKET |
	payload := make([]byte, pLen)
	copy(payload, keyID)
	copy(payload[32:], pub)
	copy(payload[64:], checkSum[:])
	copy(payload[96:], data)

	return payload, nil
}

// pingPktOnChannel build ping packet to send on the channel
func pingPktOnChannel(chn Channel, tlH *tl.TLHandler, seqno, confirmSeqno, value int64) ([]byte, error) {
	query, err := tlH.Serialize(adnl.Ping{
		Value: value,
	}, true)
	if err != nil {
		return nil, err
	}

	queryID := make([]byte, 32)
	rand.Read(queryID)

	msgQuery := adnl.Query{
		QueryID: queryID,
		Query:   query,
	}

	buff := make([]byte, 30)
	rand.Read(buff)
	rand1, rand2 := buff[:15], buff[15:]

	// packet for PING command once channel was confirmed
	pkt := adnl.PacketContent{
		Rand1:        rand1,
		Flags:        0x00c4,
		Message:      msgQuery,
		Seqno:        seqno,
		ConfirmSeqno: confirmSeqno,
		Rand2:        rand2,
	}

	data, err := tlH.Serialize(pkt, true)
	if err != nil {
		return nil, err
	}

	checkSum := sha256.Sum256(data)

	// encrypt data
	cipher, err := aes.NewCipher(chn.outEncrKey)
	if err != nil {
		return nil, err
	}

	cipher.Encrypt(data, data)

	id, err := tlH.Serialize(adnl.PublicKeyAES{
		Key: chn.outEncrKey,
	}, true)
	if err != nil {
		return nil, err
	}

	resp := make([]byte, 64+len(data))
	copy(resp, id)
	copy(resp[32:], checkSum[:])
	copy(resp[64:], data)

	return resp, nil
}

// parsePongPktOnChannel
