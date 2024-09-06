package adnl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/Gealber/dht/tl"
	"github.com/Gealber/dht/utils"
)

type Peer struct {
	// peer id
	id      []byte
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
	port    int
	conn    net.Conn
	tlH     *tl.TLHandler

	// channels in the context of adnl protocol, read doc/adnl/adnl-udp.md for more details
	chns   map[string]channel
	logger *log.Logger
	// TODO: add a closer channel to handle close connection
}

type channel struct {
	id               []byte
	outEncryptionKey []byte
	inDecryptionKey  []byte
}

func New(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey, port int) (*Peer, error) {
	var err error
	if len(pubKey) != ed25519.PublicKeySize || len(privKey) != ed25519.PrivateKeySize {
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	tlH := tl.New()
	tlH.Register(tl.DefaultTLModel)

	// register defaults models
	id, err := tlH.Serialize(tl.PublicKeyED25519{
		Key: pubKey,
	}, true)
	if err != err {
		return nil, err
	}

	return &Peer{
		id:      id,
		port:    port,
		privKey: privKey,
		pubKey:  pubKey,
		tlH:     tlH,
		chns:    make(map[string]channel),
		logger:  log.New(os.Stdout, "[adnl-peer]", log.LUTC),
	}, nil
}

// Listen will read in loop for incomming data
func (p *Peer) Listen() error {
	addr := fmt.Sprintf(":%d", p.port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}

	// read loop
	for {
		buff := make([]byte, 4096)
		n, err := conn.Read(buff)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return err
		}

		if n < 32 {
			// ignore datagrams less than 32 bytes
			continue
		}

		id := buff[:32]
		idStr := hex.EncodeToString(id)
		buff = buff[32:n]

		// if id doesn't match our peer id, check if it's a registered channel id
		if !bytes.Equal(id, p.id) {
			chnInfo, ok := p.chns[idStr]
			if !ok {
				// not a registerd neither is for us
				continue
			}

			// handle channel command
			go p.processMsgInChannel(chnInfo, buff)
			continue
		}

		// message is not to a registered channel and is for the peer
		// this messages needs to include the publick [key(32 bytes) | checksum(32 bytes) | encrypted data]
		// at least needs to be bigger than 64
		if len(buff) > 64 {
			go p.processMsgIn(buff)
		}
	}
}

// TODO: implementation
func (p *Peer) processMsgInChannel(chnInfo channel, data []byte) {
}

// TODO: implementation
func (p *Peer) processMsgIn(data []byte) {
	// extract sender public key
	senderPubKey := data[:32]
	checksum := data[32:64]
	data = data[64:]
	// let's build our shared secret as explained in the documentation
	sharedSecret, err := utils.GenerateSharedKey(p.privKey, senderPubKey)
	if err != nil {
		p.logger.Println("error generating shared key:", err)
		return
	}

	cipher, err := utils.BuildSharedCipher(sharedSecret, checksum)
	if err != nil {
		p.logger.Println("error while building shared cipher:", err)
		return
	}

	// decrypt data first, and later perform integrity validation of data
	cipher.XORKeyStream(data, data)
	localChecksum := sha256.Sum256(data)
	if !bytes.Equal(localChecksum[:], checksum) {
		p.logger.Println("failed checksum validation")
		return
	}

	// TODO: parse unencrypted packet, packet should be an adnl.packetContent
	err = p.parseMsgIn(data)
	if err != nil {
		p.logger.Println("failed parsing of message err:", err)
		return
	}
}

func (p *Peer) parseMsgIn(data []byte) error {
	var obj tl.AdnlPacketContent
	err := p.tlH.Parse(data, &obj, true)
	if err != nil {
		return err
	}

	// validate packet content
	err = p.packetContentValidation(obj)
	if err != nil {
		return err
	}

	if obj.Message != nil {
		err := handleInMsgTypes(obj.Message)
		if err != nil {
			return err
		}
	}

	for _, msg := range obj.Messages {
		err := handleInMsgTypes(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

// TODO: implement
func (p *Peer) packetContentValidation(pkt tl.AdnlPacketContent) error {
	return nil
}

func handleInMsgTypes(msg any) error {
	switch msg.(type) {
	case tl.AdnlMessageCreateChannel:
	case tl.AdnlMessageConfirmChannel:
	case tl.AdnlMessageAnswer:
	case tl.Ping:
		// answering with PONG
	case tl.Pong:
		// update metric of node who sent the PONG response
	case tl.AdnlMessageCustom:
	default:
	}

	return nil
}
