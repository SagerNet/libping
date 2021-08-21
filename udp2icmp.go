package libping

import (
	"github.com/pkg/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

type wrappedClientPacketConn struct {
	net.PacketConn
	seq int
	v6  bool
}

func (w wrappedClientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = w.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	var proto int
	if !w.v6 {
		proto = 1
	} else {
		proto = 58
	}
	message, err := icmp.ParseMessage(proto, p)
	if err != nil {
		return 0, nil, errors.WithMessage(err, "parse icmp message")
	}
	echo, ok := message.Body.(*icmp.Echo)
	if !ok {
		err = errors.New("not echo message")
	}
	p = echo.Data
	n = len(p)
	return
}

func (w wrappedClientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	w.seq++
	msg := icmp.Message{
		Body: &icmp.Echo{
			ID:   0xDBB,
			Seq:  w.seq,
			Data: p,
		},
	}
	if !w.v6 {
		msg.Type = ipv4.ICMPTypeEcho
	} else {
		msg.Type = ipv6.ICMPTypeEchoRequest
	}
	p, err = msg.Marshal(nil)
	if err != nil {
		return 0, errors.WithMessage(err, "create icmp message")
	}
	return w.PacketConn.WriteTo(p, addr)
}

func DialEcho(addr net.UDPAddr) (net.PacketConn, error) {

	v6 := addr.IP.To4() == nil
	var fd int
	var err error
	if !v6 {
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	} else {
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
	}

	if err != nil {
		return nil, errors.WithMessage(err, "create icmp socket")
	}

	f := os.NewFile(uintptr(fd), "dgram")
	conn, err := net.FilePacketConn(f)

	if err != nil {
		return nil, errors.WithMessage(err, "create icmp packet conn")
	}

	return conn, nil

}
