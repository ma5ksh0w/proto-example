package app

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/ma5ksh0w/proto-example/internal/common"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/salsa20"
)

type state struct {
	sessions map[common.Hash256]*Session
	pending  map[common.Hash256]*PendingSession
}

type sendMessage struct {
	to     string
	addr   *net.UDPAddr
	msg    string
	result chan<- error
}

type Client struct {
	pub  common.PubKey
	priv common.PrivKey
	name string
	addr *net.UDPAddr

	fd *net.UDPConn

	close   chan struct{}
	recv    chan *readPacket
	send    chan sendMessage
	getsess chan chan<- []common.Hash256

	onPayload func(from string, data string)

	wg sync.WaitGroup
}

func New(name string, addr string, onPayload func(string, string)) (*Client, error) {
	pub, priv, err := common.GenerateKeypair()
	if err != nil {
		return nil, err
	}

	la, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	fd, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}

	c := &Client{
		pub:       *pub,
		priv:      *priv,
		name:      name,
		addr:      la,
		fd:        fd,
		close:     make(chan struct{}),
		recv:      make(chan *readPacket),
		send:      make(chan sendMessage),
		getsess:   make(chan chan<- []common.Hash256),
		onPayload: onPayload,
	}

	c.wg.Add(2)
	go c.run()
	go c.reader()

	return c, nil
}

func (c *Client) run() {
	defer c.wg.Done()

	state := &state{
		sessions: make(map[common.Hash256]*Session),
		pending:  make(map[common.Hash256]*PendingSession),
	}

loop:
	for {
		select {
		case <-c.close:
			break loop

		case msg := <-c.recv:
			if err := c.handlePacket(state, msg); err != nil {
				log15.Error("Handle packet", "error", err)
			}

		case req := <-c.send:
			if req.addr != nil {
				msg := &AnnounceMessage{
					Client: &Info{
						PublicKey: &c.pub,
						Address:   c.addr,
						Name:      c.name,
					},
				}

				rand.Read(msg.SessionID[:])
				pub, priv, err := box.GenerateKey(rand.Reader)
				if err != nil {
					req.result <- err
				} else {
					msg.PublicKey = *pub
					state.pending[msg.SessionID] = &PendingSession{
						Hash: msg.SessionID,
						Priv: *priv,
						Pub:  *pub,
					}

					req.result <- c.sendMessage(req.addr, nil, CodeAnnounce, msg.Bytes())
				}
			} else {
				var id common.Hash256
				copy(id[:], common.Base58Decode(req.to))

				if sess, ok := state.sessions[id]; ok {
					req.result <- c.sendMessage(sess.Address, sess, CodePayload, []byte(req.msg))
				} else {
					req.result <- errors.New("not found")
				}
			}

		case ch := <-c.getsess:
			ids := []common.Hash256{}
			for id := range state.sessions {
				ids = append(ids, id)
			}

			ch <- ids
		}
	}

	for id := range state.sessions {
		delete(state.sessions, id)
	}

	c.fd.Close()
}

func (c *Client) handlePacket(state *state, p *readPacket) error {
	var (
		sessionID common.Hash256
		sig       common.SigData
	)

	copy(sessionID[:], p.message.Header().ID())
	copy(sig[:], p.message.Header().Signature())

	if sess, ok := state.sessions[sessionID]; ok {
		if !common.Verify(sess.PublicKey, p.message.Payload(), &sig) {
			return errors.New("invalid signature")
		}

		salsa20.XORKeyStream(p.message.Payload(), p.message.Payload(), p.message.Header().Nonce(), (*[32]byte)(&sess.SharedKey))
	} else if int(p.message.Header().Code()[0]) != CodeAnnounce && int(p.message.Header().Code()[0]) != CodeNotAnnounced {
		return c.sendMessage(p.address, nil, CodeNotAnnounced, nil)
	}

	size := int(binary.BigEndian.Uint16(p.message.Header().Size()))
	data := p.message.Payload()[:size]

	switch int(p.message.Header().Code()[0]) {
	case CodeAnnounce:
		var (
			sk   [32]byte
			resp *AnnounceMessage
		)

		msg, err := ParseAnnounceMessage(data)
		if err != nil {
			return err
		}

		if !common.Verify(msg.Client.PublicKey, p.message.Payload(), &sig) {
			return errors.New("invalid signature")
		}

		if ps, ok := state.pending[msg.SessionID]; ok {
			box.Precompute(&sk, &msg.PublicKey, &ps.Priv)
			delete(state.pending, msg.SessionID)
		} else {
			pub, priv, err := box.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}

			box.Precompute(&sk, &msg.PublicKey, priv)
			resp = &AnnounceMessage{
				PublicKey: *pub,
				SessionID: msg.SessionID,
				Client: &Info{
					PublicKey: &c.pub,
					Address:   c.addr,
					Name:      c.name,
				},
			}
		}

		state.sessions[msg.SessionID] = &Session{
			Hash:        msg.SessionID,
			SharedKey:   sk,
			Address:     p.address,
			PublicKey:   msg.Client.PublicKey,
			Client:      msg.Client,
			Started:     time.Now(),
			LastReceive: time.Now(),
		}

		log15.Info("Client connected", "session", msg.SessionID, "id", msg.Client.PublicKey)
		if resp != nil {
			return c.sendMessage(p.address, nil, CodeAnnounce, resp.Bytes())
		}

	case CodeNotAnnounced:
		msg := &AnnounceMessage{
			Client: &Info{
				PublicKey: &c.pub,
				Address:   c.addr,
				Name:      c.name,
			},
		}

		rand.Read(msg.SessionID[:])
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}

		msg.PublicKey = *pub
		state.pending[msg.SessionID] = &PendingSession{
			Hash: msg.SessionID,
			Priv: *priv,
			Pub:  *pub,
		}

		return c.sendMessage(p.address, nil, CodeAnnounce, msg.Bytes())

	case CodePayload:
		c.onPayload(sessionID.String(), string(data))

	default:
		return errors.New("invalid code")
	}

	return nil
}

func (c *Client) sendMessage(addr *net.UDPAddr, sess *Session, code int, data []byte) error {
	var b block

	if sess != nil {
		copy(b.Header().ID(), sess.Hash[:])
	}

	b.Header().Code()[0] = byte(code)
	binary.BigEndian.PutUint16(b.Header().Size(), uint16(len(data)))

	copy(b.Payload(), data)
	if sess != nil {
		rand.Read(b.Header().Nonce())
		salsa20.XORKeyStream(b.Payload(), b.Payload(), b.Header().Nonce(), (*[32]byte)(&sess.SharedKey))
	}

	copy(b.Header().Signature(), common.Sign(&c.priv, b.Payload())[:])
	_, err := c.fd.WriteToUDP(b[:], addr)
	return err
}

func (c *Client) reader() {
	defer c.wg.Done()

	var b block
	for {
		_, addr, err := c.fd.ReadFromUDP(b[:])
		if err != nil {
			log15.Error("Conn closed", "error", err)
			select {
			case <-c.close:
			default:
				close(c.close)
			}

			return
		}

		p := &readPacket{address: addr}
		copy(p.message[:], b[:])

		select {
		case <-c.close:
			return
		case c.recv <- p:
		}
	}
}

func (c *Client) SendMessageTo(id, msg string) error {
	e := make(chan error)
	select {
	case <-c.close:
		return errors.New("closed")
	case c.send <- sendMessage{
		to:     id,
		msg:    msg,
		result: e,
	}:
		return <-e
	}
}

func (c *Client) SendMessageToAddr(addr, msg string) error {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	e := make(chan error)
	select {
	case <-c.close:
		return errors.New("closed")
	case c.send <- sendMessage{
		addr:   a,
		msg:    msg,
		result: e,
	}:
		return <-e
	}
}

func (c *Client) Sessions() []common.Hash256 {
	ch := make(chan []common.Hash256)
	select {
	case <-c.close:
		return nil
	case c.getsess <- ch:
		return <-ch
	}
}

func (c *Client) Close() error {
	select {
	case <-c.close:
	default:
		close(c.close)
	}

	c.wg.Wait()
	return nil
}
