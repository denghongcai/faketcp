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
	status         int // 0: init, 1: sync, 2: established
}

func (this *PacketConn) Read(b []byte) (int, error) {
	n, _, err := this.ReadFrom(b)
	return n, err
}

// ReadFrom read packet from raw socket
func (this *PacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	tcp, payload, addr, err := this.readFromChan()
	if err != nil {
		return 0, addr, err
	}
	if tcp.URG {
		debug("receive tcp data packet from %s:%d", addr.String(), this.tcpLocalAddr.Port)
		if payload != nil {
			copy(buf[:len(*payload)], *payload)
			return len(*payload), addr, err
		}
		return 0, addr, errors.New("packet doesn't contain payload")
	}
	if tcp.SYN {
		debug("receive tcp syn data packet from %s:%d", addr.String(), this.tcpLocalAddr.Port)
		this.writeSynAck(addr)
	}

	return 0, addr, err
}

func (this *PacketConn) readFromChan() (*layers.TCP, *[]byte, net.Addr, error) {
	addr := &net.UDPAddr{}
	packet, ok := <-this.readPacketChan
	if !ok {
		return &layers.TCP{}, nil, addr, errors.New("read channel has been closed")
	} else {
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, ok := ipLayer.(*layers.IPv4)
			if !ok {
				return &layers.TCP{}, nil, addr, errors.New("packet doesn't contain ipv4 layer")
			}
			addr.IP = ip.SrcIP
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					return &layers.TCP{}, nil, addr, errors.New("packet doesn't contain tcp layer")
				}
				srcPortRef := reflect.ValueOf(tcp.SrcPort)
				addr.Port = int(srcPortRef.Uint())
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					payload := applicationLayer.Payload()
					return tcp, &payload, addr, nil
				}

				return tcp, nil, addr, nil
			}
		}
	}
	return &layers.TCP{}, nil, addr, nil
}

func (this *PacketConn) Write(b []byte) (int, error) {
	n, err := this.WriteTo(b, &this.tcpRemoteAddr)
	return n, err
}

// WriteTo write packet to raw socket
func (this *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpRemoteAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, &net.OpError{Op: "writre", Addr: addr, Err: syscall.EINVAL}
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(this.tcpLocalAddr.Port),
		DstPort: layers.TCPPort(udpRemoteAddr.Port),
		Seq:     this.seq,
		URG:     true,
		Window:  14600,
	}
	return this.writeToBase(&b, tcpLayer, udpRemoteAddr)
}

// WriteSyn write syn packet to raw socket
func (this *PacketConn) writeSyn(addr net.Addr) error {
	udpRemoteAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return &net.OpError{Op: "writre", Addr: addr, Err: syscall.EINVAL}
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(this.tcpLocalAddr.Port),
		DstPort: layers.TCPPort(udpRemoteAddr.Port),
		Seq:     this.seq,
		SYN:     true,
		Window:  14600,
	}
	var payload []byte
	_, err := this.writeToBase(&payload, tcpLayer, udpRemoteAddr)
	return err
}

// WriteSynAck write syn-ack packet to raw socket
func (this *PacketConn) writeSynAck(addr net.Addr) error {
	udpRemoteAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return &net.OpError{Op: "writre", Addr: addr, Err: syscall.EINVAL}
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(this.tcpLocalAddr.Port),
		DstPort: layers.TCPPort(udpRemoteAddr.Port),
		Seq:     this.seq,
		SYN:     true,
		Ack:     this.seq + 1,
		Window:  14600,
	}
	var payload []byte
	_, err := this.writeToBase(&payload, tcpLayer, udpRemoteAddr)
	return err
}

func (this *PacketConn) writeToBase(payload *[]byte, tcpLayer *layers.TCP, udpRemoteAddr *net.UDPAddr) (int, error) {
	ip := &layers.IPv4{
		SrcIP:    this.tcpLocalAddr.IP,
		DstIP:    udpRemoteAddr.IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcpLayer, gopacket.Payload(*payload)); err != nil {
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
	return len(*payload), nil
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
	packetConn.writeSyn(conn.RemoteAddr())
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
