package app_test

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/ma5ksh0w/proto-example/internal/app"
	"github.com/ma5ksh0w/proto-example/internal/common"
)

func TestParseInfo(t *testing.T) {
	var pub common.PubKey
	rand.Read(pub[:])

	info := &app.Info{
		PublicKey: &pub,
		Address:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222},
		Name:      "test-user",
	}

	data := info.Bytes()

	info2, err := app.ParseInfo(data)
	if err != nil {
		t.Fatal(err)
	}

	if !info2.PublicKey.Equal(info.PublicKey) {
		t.Fatal("pubkey invalid")
	}

	if info2.Name != info.Name {
		t.Fatal("name invalid")
	}

	if !info2.Address.IP.Equal(info.Address.IP) {
		t.Fatal("invalid ip")
	}

	if info2.Address.Port != info.Address.Port {
		t.Fatal("invalid port")
	}
}
