package main

import (
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketConn struct {
	localAddr     net.Addr
	tcpLocalAddr  net.TCPAddr
	tcpRemoteAddr net.TCPAddr
	conn          net.PacketConn
}

type Addr struct {
}

func (this Addr) String() string {
	return ""
}

func (this Addr) Network() string {
	return ""
}

func (this *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := this.conn.ReadFrom(b)
	if err != nil {
		return -1, addr, err
	} else if addr.String() == this.tcpRemoteAddr.IP.String() {
		packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			if tcp.DstPort.String() == string(this.tcpLocalAddr.Port) {
				copy(b[:len(tcp.Payload)], tcp.Payload[:])
				return len(tcp.Payload), addr, nil
			}
		}
	}
	return -1, Addr{}, nil
}

func (this *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ip := &layers.IPv4{
		SrcIP:    this.tcpLocalAddr.IP,
		DstIP:    this.tcpRemoteAddr.IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(this.tcpLocalAddr.Port),
		DstPort: layers.TCPPort(this.tcpRemoteAddr.Port),
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return -1, err
	}
	n, err := this.conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: this.tcpRemoteAddr.IP})
	if err != nil {
		return -1, err
	}
	if n != len(b) {
		return -1, errors.New("data is not sent")
	}
	return len(b), nil
}

func (this *PacketConn) Close() error {
	err := this.conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (this *PacketConn) LocalAddr() net.Addr {
	return this.localAddr
}

func (this *PacketConn) SetDeadline(t time.Time) error {
	err := this.conn.SetDeadline(t)
	if err != nil {
		return err
	}
	return nil
}

func (this *PacketConn) SetReadDeadline(t time.Time) error {
	err := this.conn.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return nil
}

func (this *PacketConn) SetWriteDeadline(t time.Time) error {
	err := this.conn.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	return nil
}

func Dial(network string, address string) (*PacketConn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	tcpLocalAddr, err := net.ResolveTCPAddr(network, conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	pconn, err := net.ListenPacket("ip:"+network, tcpLocalAddr.IP.String())
	if err != nil {
		return nil, err
	}
	tcpRemoteAddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}
	packetConn := &PacketConn{
		localAddr:     conn.LocalAddr(),
		tcpLocalAddr:  *tcpLocalAddr,
		tcpRemoteAddr: *tcpRemoteAddr,
		conn:          pconn,
	}
	return packetConn, nil
}
