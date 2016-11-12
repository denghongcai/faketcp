package faketcp

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	DebugLog "github.com/tj/go-debug"
)

var debug = DebugLog.Debug("faketcp")

// PacketConn implemented net.PacketConn
type PacketConn struct {
	seqMutex       sync.Mutex
	seq            uint32
	localAddr      net.Addr
	remoteAddr     net.Addr
	tcpLocalAddr   net.TCPAddr
	tcpRemoteAddr  net.TCPAddr
	conn           net.PacketConn
	readPacketChan chan gopacket.Packet
	isServer       bool
	closed         bool
}

func (this *PacketConn) Read(b []byte) (int, error) {
	n, _, err := this.ReadFrom(b)
	return n, err
}

// ReadFrom read packet from raw socket
func (this *PacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	packet, ok := <-this.readPacketChan
	if !ok {
		return 0, &net.UDPAddr{}, errors.New("read channel has been closed")
	} else {
		addr := &net.UDPAddr{}
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, ok := ipLayer.(*layers.IPv4)
			if !ok {
				return 0, addr, errors.New("packet doesn't contain ipv4 layer")
			}
			addr.IP = ip.SrcIP
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				return 0, &net.UDPAddr{}, errors.New("packet doesn't contain tcp layer")
			}
			srcPortRef := reflect.ValueOf(tcp.SrcPort)
			addr.Port = int(srcPortRef.Uint())

			if tcp.URG {
				debug("receive tcp packet from %s:%d", addr.String(), this.tcpLocalAddr.Port)
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					payload := applicationLayer.Payload()
					copy(buf[:len(payload)], payload)
					return len(payload), addr, nil
				}
				return 0, addr, errors.New("packet doesn't contain application layer")
			}
		}
	}
	return 0, &net.UDPAddr{}, nil
}

func (this *PacketConn) Write(b []byte) (int, error) {
	n, err := this.WriteTo(b, &this.tcpRemoteAddr)
	return n, err
}

// WriteTo write packet to raw socket
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
	debug("writed to %s, seq is %d", udpRemoteAddr.String(), this.seq)
	this.seqMutex.Lock()
	this.seq = this.seq + 1
	defer this.seqMutex.Unlock()
	return len(b), nil
}

// Close close the underlying raw socket
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

func (this *PacketConn) getLocalDev() (string, error) {
	dev := ""
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return dev, err
	}

	for _, d := range devs {
		for _, a := range d.Addresses {
			if a.IP.String() == this.tcpLocalAddr.IP.String() {
				dev = d.Name
			}
		}
	}

	if dev == "" {
		return dev, errors.New("could not find the appropriate adapter device")
	}
	return dev, nil
}

func (this *PacketConn) initReceiver() error {
	devName, err := this.getLocalDev()
	if err != nil {
		return err
	}
	bpf := ""
	if this.isServer {
		bpf = fmt.Sprintf("tcp and dst port %d and dst host %s", this.tcpLocalAddr.Port, this.tcpLocalAddr.IP.String())
	} else {
		bpf = fmt.Sprintf("tcp and dst port %d and src host %s", this.tcpLocalAddr.Port, this.tcpRemoteAddr.IP.String())
	}
	if handle, err := pcap.OpenLive(devName, 8192, true, pcap.BlockForever); err != nil {
		return err
	} else if err := handle.SetBPFFilter(bpf); err != nil {
		return err
	} else {
		debug("BPF filter: %s", bpf)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.NoCopy = true
		packetSource.Lazy = true
		this.readPacketChan = packetSource.Packets()
		debug("receiver inited")
		return nil
	}
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
	debug("connected to %s", tcpRemoteAddr.String())
	packetConn := &PacketConn{
		localAddr:     conn.LocalAddr(),
		remoteAddr:    conn.RemoteAddr(),
		tcpLocalAddr:  *tcpLocalAddr,
		tcpRemoteAddr: *tcpRemoteAddr,
		conn:          pconn,
		seq:           0,
	}
	if err := packetConn.initReceiver(); err != nil {
		return nil, err
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
	debug("listening on %s", tcpLocalAddr.String())
	packetConn := &PacketConn{
		tcpLocalAddr: *tcpLocalAddr,
		localAddr:    tcpLocalAddr,
		conn:         pconn,
		isServer:     true,
	}
	if err := packetConn.initReceiver(); err != nil {
		return nil, err
	}
	return packetConn, nil
}
