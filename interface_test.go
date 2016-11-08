package faketcp

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestDial(t *testing.T) {
	conn, err := Dial("tcp", "www.baidu.com:80")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(conn.LocalAddr().String())
}

func TestDialAndListen(t *testing.T) {
	sconn, err := Listen("tcp", "127.0.0.1:8000")
	if err != nil {
		t.Error(err)
		return
	}
	c := make(chan bool)
	go func() {
		for {
			b := make([]byte, 4096)
			t.Log("reading from conn")
			n, _, err := sconn.ReadFrom(b)
			if err != nil {
				t.Log(err)
				continue
			}
			if bytes.Equal([]byte{1, 2, 3}, b[:n]) {
				c <- true
			}
		}
	}()
	conn, err := Dial("tcp", "127.0.0.1:8000")
	if err != nil {
		t.Error(err)
	}
	b := []byte{1, 2, 3}
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8000")
	if err != nil {
		t.Error(err)
	}
	_, err = conn.WriteTo(b, addr)
	if err != nil {
		t.Error(err)
	}
	select {
	case <-c:
	case <-time.After(time.Second * 1):
		t.Fail()
	}
}
