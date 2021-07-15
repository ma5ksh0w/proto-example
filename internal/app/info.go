package app

import (
	"errors"
	"net"

	"github.com/ma5ksh0w/proto-example/internal/common"
)

type Info struct {
	PublicKey *common.PubKey
	Address   *net.UDPAddr
	Name      string
}

func ParseInfo(data []byte) (*Info, error) {
	var pub common.PubKey
	if len(data) < 34 {
		return nil, errors.New("invalid info: data too short")
	}

	copy(pub[:], data[:32])

	addrLen := int(data[32])
	if len(data) < addrLen+33 {
		return nil, errors.New("invalid info: data too short")
	}

	addr, err := net.ResolveUDPAddr("udp", string(data[33:][:addrLen]))
	if err != nil {
		return nil, err
	}

	return &Info{
		PublicKey: &pub,
		Address:   addr,
		Name:      string(data[33+addrLen:]),
	}, nil
}

func (info *Info) Bytes() (data []byte) {
	astr := []byte(info.Address.String())
	data = append(data, info.PublicKey[:]...)
	data = append(data, byte(len(astr)))
	data = append(data, astr...)
	return append(data, []byte(info.Name)...)
}

type AnnounceMessage struct {
	PublicKey [32]byte
	SessionID [32]byte
	Client    *Info
}

func ParseAnnounceMessage(data []byte) (*AnnounceMessage, error) {
	var msg AnnounceMessage

	if len(data) < 64 {
		return nil, errors.New("message too short")
	}

	copy(msg.SessionID[:], data[:32])
	copy(msg.PublicKey[:], data[32:][:32])
	info, err := ParseInfo(data[64:])
	if err != nil {
		return nil, err
	}

	msg.Client = info
	return &msg, nil
}

func (msg *AnnounceMessage) Bytes() []byte {
	data := msg.SessionID[:]
	data = append(data, msg.PublicKey[:]...)
	return append(data, msg.Client.Bytes()...)
}
