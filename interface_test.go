package faketcp

import (
	"bytes"
	"flag"
	"net"
	"os"
	"testing"
	"time"
)

const address = "127.0.0.1:1992"

func server() {
	conn, err := Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil || n == 0 {
			continue
		}
		tcpRemoteAddr, ok := addr.(*net.TCPAddr)
		if !ok {
			continue
		}
		conn.WriteTo(b[:n], tcpRemoteAddr)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	go server()
	os.Exit(m.Run())
}

func TestDial(t *testing.T) {
	conn, err := Dial("tcp", "www.baidu.com:80")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(conn.LocalAddr().String())
}

func TestDialAndListen(t *testing.T) {
	c := make(chan bool)
	conn, err := Dial("tcp", address)
	if err != nil {
		t.Error(err)
	}
	buf := []byte{1, 2, 3}
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		t.Error(err)
	}
	go func() {
		for {
			rb := make([]byte, 4096)
			n, _, err := conn.ReadFrom(rb)
			if err != nil {
				continue
			}
			if bytes.Equal(buf, rb[:n]) {
				c <- true
			}
		}
	}()
	_, err = conn.WriteTo(buf, addr)
	if err != nil {
		t.Error(err)
	}
	select {
	case <-c:
	case <-time.After(time.Second * 1):
		t.Fail()
	}
}
