package app

import (
	"net"

	"github.com/ma5ksh0w/proto-example/internal/common"
)

const (
	CodeAnnounce = iota
	CodeNotAnnounced
	CodePayload

	CodeCloseSession = 0xFF
)

type Packet struct {
	Address *net.UDPAddr
	Hash    common.Hash256
	Code    int
	Payload []byte
}

type header []byte

func (h header) CRC() []byte       { return h[:4] }
func (h header) ID() []byte        { return h[4:][:32] }
func (h header) Code() []byte      { return h[36:][:1] }
func (h header) Size() []byte      { return h[37:][:2] }
func (h header) Nonce() []byte     { return h[39:][:24] }
func (h header) Signature() []byte { return h[63:][:64] }

type block [1024]byte

func (b *block) Header() header  { return b[:127] }
func (b *block) Payload() []byte { return b[127:] }

type readPacket struct {
	address *net.UDPAddr
	message block
}
