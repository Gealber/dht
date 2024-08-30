package adnl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Gealber/dht/tl"
)

type Peer struct {
	// peer id
	id      []byte
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
	port    int
	conn    net.Conn
	tlH     *tl.TLHandler

	chns map[string]channel
	// add a closer channel to handle close connection
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
		go p.processMsgIn(buff)
	}
}

// TODO: implementation
func (p *Peer) processMsgInChannel(chnInfo channel, data []byte) {
}

// TODO: implementation
func (p *Peer) processMsgIn(data []byte) {}
