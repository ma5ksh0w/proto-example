package app

import (
	"net"
	"time"

	"github.com/ma5ksh0w/proto-example/internal/common"
)

type Session struct {
	Hash        common.Hash256
	SharedKey   common.Hash256
	PublicKey   *common.PubKey
	Address     *net.UDPAddr
	Client      *Info
	Started     time.Time
	LastReceive time.Time
}

type PendingSession struct {
	Hash   common.Hash256
	Priv   [32]byte
	Pub    [32]byte
	Client *Info
}
