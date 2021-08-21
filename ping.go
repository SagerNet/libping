package libping

import (
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strings"
	"time"
)

const payload = "abcdefghijklmnopqrstuvwabcdefghi"

func IcmpPing(address string, timeout int) (int, error) {
	i := net.ParseIP(address)
	if i == nil {
		return 0, fmt.Errorf("unable to parse ip %s", address)
	}
	var err error
	v6 := i.To4() == nil
	var fd int
	if !v6 {
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	} else {
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
	}

	f := os.NewFile(uintptr(fd), "dgram")
	conn, err := net.FilePacketConn(f)
	if err != nil {
		return 0, errors.WithMessage(err, "create conn")
	}

	defer func(conn net.PacketConn) {
		_ = conn.Close()
	}(conn)

	start := time.Now().UnixMilli()
	for seq := 1; timeout > 0; seq++ {
		var sockTo int
		if timeout > 1000 {
			sockTo = 1000
		} else {
			sockTo = timeout
		}
		timeout -= sockTo

		err := conn.SetReadDeadline(time.Now().Add(time.Duration(sockTo) * time.Millisecond))
		if err != nil {
			return 0, errors.WithMessage(err, "set read timeout")
		}

		msg := icmp.Message{
			Body: &icmp.Echo{
				ID:   0xDBB,
				Seq:  seq,
				Data: []byte(payload),
			},
		}
		if !v6 {
			msg.Type = ipv4.ICMPTypeEcho
		} else {
			msg.Type = ipv6.ICMPTypeEchoRequest
		}

		data, err := msg.Marshal(nil)
		if err != nil {
			return 0, errors.WithMessage(err, "make icmp message")
		}

		_, err = conn.WriteTo(data, &net.UDPAddr{
			IP:   i,
			Port: 0,
		})
		if err != nil {
			return 0, errors.WithMessage(err, "write icmp message")
		}

		_, _, err = conn.ReadFrom(data)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				continue
			}

			return 0, errors.WithMessage(err, "read icmp message")
		}

		delay := time.Now().UnixMilli() - start
		return int(delay), nil
	}

	return -1, nil
}
