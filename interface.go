package faketcp

import (
	"errors"
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

func (this *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := this.conn.ReadFrom(b)
	if err != nil {
		return 0, addr, err
	} else if this.isServer || addr.String() == this.tcpRemoteAddr.IP.String() {
		packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.NoCopy)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				return 0, addr, errors.New("packet doesn't contain tcp layer")
			}

			dstPortRef := reflect.ValueOf(tcp.DstPort)
			if int(dstPortRef.Uint()) == this.tcpLocalAddr.Port && tcp.URG {
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					payload := applicationLayer.Payload()
					copy(b[:len(payload)], payload[:])
					return len(payload), addr, nil
				}
				return 0, addr, errors.New("packet doesn't contain application layer")
			}
		}
	}
	return 0, Addr{}, &net.OpError{Op: "read", Err: syscall.EIO}
}

func (this *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	tcpRemoteAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return 0, &net.OpError{Op: "write", Addr: addr, Err: syscall.EINVAL}
	}
	ip := &layers.IPv4{
		SrcIP:    this.tcpLocalAddr.IP,
		DstIP:    tcpRemoteAddr.IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(this.tcpLocalAddr.Port),
		DstPort: layers.TCPPort(tcpRemoteAddr.Port),
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
	n, err := this.conn.WriteTo(bufBytes, &net.IPAddr{IP: tcpRemoteAddr.IP})
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
		seq:           0,
	}
	return packetConn, nil
}

func Listen(network, address string) (*PacketConn, error) {
	tcpLocalAddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}
	pconn, err := net.ListenPacket("ip:"+network, tcpLocalAddr.IP.String())
	if err != nil {
		return nil, err
	}
	return &PacketConn{
		tcpLocalAddr: *tcpLocalAddr,
		conn:         pconn,
		isServer:     true,
	}, nil
}
