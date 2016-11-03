package main

import "testing"

func TestDial(t *testing.T) {
	conn, err := Dial("tcp", "www.baidu.com:80")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(conn.LocalAddr().String())
}
