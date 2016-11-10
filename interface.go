package faketcp

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketConn struct {
	seq           uint32
	localAddr     net.Addr
	remoteAddr    net.Addr
	tcpLocalAddr  net.TCPAddr
	tcpRemoteAddr net.TCPAddr
	conn          net.PacketConn
	isServer      bool
}

type Addr struct {
}

func (this Addr) String() string {
	return ""
}

func (this Addr) Network() string {
	return ""
}

func (this *PacketConn) Read(b []byte) (int, error) {
	n, _, err := this.ReadFrom(b)
	return n, err
}

func (this *PacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	b := make([]byte, 4096)
	n, addr, err := this.conn.ReadFrom(b)
	if err != nil {
		return 0, addr, err
	} else if this.isServer || addr.String() == this.tcpRemoteAddr.IP.String() {
		packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				return 0, addr, errors.New("packet doesn't contain tcp layer")
			}

			dstPortRef := reflect.ValueOf(tcp.DstPort)
			if int(dstPortRef.Uint()) == this.tcpLocalAddr.Port && tcp.URG {
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					srcPortRef := reflect.ValueOf(tcp.SrcPort)
					udpSrcAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addr.String(), srcPortRef.Uint()))
					payload := applicationLayer.Payload()
					copy(buf[:len(payload)], payload)
					return len(payload), udpSrcAddr, nil
				}
				return 0, addr, errors.New("packet doesn't contain application layer")
			}
		}
	}
	return 0, Addr{}, nil
}

func (this *PacketConn) Write(b []byte) (int, error) {
	n, err := this.WriteTo(b, &this.tcpRemoteAddr)
	return n, err
}

func (this *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpRemoteAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, &net.OpError{Op: "write", Addr: addr, Err: syscall.EINVAL}
	}
	ip := &layers.IPv4{
		SrcIP:    this.tcpLocalAddr.IP,
		DstIP:    udpRemoteAddr.IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(this.tcpLocalAddr.Port),
		DstPort: layers.TCPPort(udpRemoteAddr.Port),
		Seq:     this.seq,
		URG:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp, gopacket.Payload(b)); err != nil {
		return 0, err
	}
	bufBytes := buf.Bytes()
	n, err := this.conn.WriteTo(bufBytes, &net.IPAddr{IP: udpRemoteAddr.IP})
	if err != nil {
		return 0, err
	}
	if n != len(bufBytes) {
		return 0, errors.New("data is not sent")
	}
	this.seq = this.seq + 1
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

func (this *PacketConn) RemoteAddr() net.Addr {
	return this.remoteAddr
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

func Dial(network, address string) (*PacketConn, error) {
	udpRemoteAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpRemoteAddr)
	if err != nil {
		return nil, err
	}
	tcpLocalAddr, err := net.ResolveTCPAddr("tcp", conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	pconn, err := net.ListenPacket("ip:tcp", tcpLocalAddr.IP.String())
	if err != nil {
		return nil, err
	}
	tcpRemoteAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	packetConn := &PacketConn{
		localAddr:     conn.LocalAddr(),
		remoteAddr:    conn.RemoteAddr(),
		tcpLocalAddr:  *tcpLocalAddr,
		tcpRemoteAddr: *tcpRemoteAddr,
		conn:          pconn,
		seq:           0,
	}
	return packetConn, nil
}

func Listen(network, address string) (*PacketConn, error) {
	tcpLocalAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	pconn, err := net.ListenPacket("ip:tcp", tcpLocalAddr.IP.String())
	if err != nil {
		return nil, err
	}
	return &PacketConn{
		tcpLocalAddr: *tcpLocalAddr,
		localAddr:    tcpLocalAddr,
		conn:         pconn,
		isServer:     true,
	}, nil
}
