package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"math"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/FloatTech/ttl"
	"github.com/fumiama/orbyte/pbuf"
	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/dns"
	"github.com/fumiama/terasu/ip"
	"github.com/sirupsen/logrus"
)

var (
	freeconn     = uintptr(0)
	tlsconnCache = ttl.NewCacheOn(
		5*time.Minute, [4]func(uint8, net.Conn){
			nil, nil, func(_ uint8, c net.Conn) {
				logrus.Warnln("Close idle/error tls conn to", c.RemoteAddr())
				_ = c.Close()
			}, nil,
		})
	fallback *net.UDPAddr
	forcefb  bool
	timeout  uint
)

func main() {
	iphost := flag.String("l", "127.0.0.1:5345", "listen DNS UDP port")
	fbsrv := flag.String("fb", "127.0.0.1:53", "fallback to DNS UDP port")
	debug := flag.Bool("d", false, "show debug log")
	flag.UintVar(&timeout, "to", 4, "dial timeout in sec")
	flag.BoolVar(&forcefb, "ffb", false, "force using fallback")
	flag.BoolVar(&ip.IsIPv6Available, "6", false, "use ipv6 servers")
	frag := flag.Uint("frag", 4, "TLS first fragemt size (0 to disable)")
	flag.Parse()

	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if frag != nil {
		terasu.DefaultFirstFragmentLen = int(*frag)
	}

	if *fbsrv != "" {
		addrport, err := netip.ParseAddrPort(*fbsrv)
		if err != nil {
			logrus.Fatal("ParseAddrPort err:", err)
		}
		fallback = net.UDPAddrFromAddrPort(addrport)
		logrus.Infoln("Set fallback server to", fallback)
	}

	dns.SetTimeout(time.Second * time.Duration(timeout))

	logrus.Infoln("Use ipv6 servers:", ip.IsIPv6Available)

	addrport, err := netip.ParseAddrPort(*iphost)
	if err != nil {
		logrus.Fatal("ParseAddrPort err:", err)
	}

	laddr := net.UDPAddrFromAddrPort(addrport)

RECONN:
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logrus.Fatal("ListenUDP err:", err)
	}
	logrus.Infoln("Listen at", conn.LocalAddr())

	// server loop
	buf := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logrus.Warnln("ReadFromUDP err:", err)
			goto RECONN
		}
		logrus.Debugln("ReadFromUDP from", addr, "with", n, "bytes payload")
		payload := pbuf.NewBytes(n)
		payload.V(func(b []byte) { copy(b, buf[:n]) })
		cnt := lockfree()
		if cnt == math.MaxUint8 {
			logrus.Warnln("Drop request from", addr, "due to rate limit")
			continue
		}
		go response(cnt, conn, addr, payload)
	}
}

func response(cnt uint8, conn *net.UDPConn, addr *net.UDPAddr, payload pbuf.Bytes) {
	var (
		err     error
		tlsconn net.Conn
		loopcnt = 0
		ctx     context.Context
		cancel  context.CancelFunc
	)

	if forcefb {
		goto FALLBACK
	}

	defer releasefree(cnt)
	logrus.Debugln(addr, "Run on lock", cnt)

REDAIL:
	ctx, cancel = context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
	defer cancel()
	tlsconn, err = dialtls(cnt, ctx)
	if err != nil {
		logrus.Warnln(addr, "Dial DNS server err:", err)
		return
	}
	logrus.Debugln(addr, "Dial to DNS server", tlsconn.RemoteAddr())

	payload.V(func(b []byte) {
		var plen [2]byte
		binary.BigEndian.PutUint16(plen[:], uint16(len(b)))
		_, err = io.Copy(tlsconn, &net.Buffers{plen[:], b})
		if err != nil {
			return
		}
		logrus.Debugln(addr, "Write to DNS server", tlsconn.RemoteAddr())
		pbuf.BufferItemToBytes(pbuf.NewBuffer(nil).P(func(b *pbuf.Buffer) {
			var plen [2]byte
			_, err = io.ReadFull(tlsconn, plen[:])
			if err != nil {
				return
			}
			payloadlen := int64(binary.BigEndian.Uint16(plen[:]))
			logrus.Debugln(addr, "Read payload len", payloadlen, "from DNS server", tlsconn.RemoteAddr())
			_, err = io.CopyN(b, tlsconn, payloadlen)
			if err != nil {
				return
			}
			logrus.Debugln(addr, "Read", b.Len(), "bytes from DNS server", tlsconn.RemoteAddr())
		})).V(func(b []byte) {
			if err != nil {
				return
			}
			_, err = conn.WriteToUDP(b, addr)
			if err != nil {
				return
			}
			logrus.Debugln("Write response to", addr)
		})
	})
	if err == nil {
		return
	}
	logrus.Warnln(addr, "Proxy to DNS server err:", err)
	tlsconnCache.Delete(cnt)
	loopcnt++
	if loopcnt < 2 {
		goto REDAIL
	}
FALLBACK:
	fbconn, err := net.DialUDP("udp", nil, fallback) // dummy fill
	if err != nil {
		logrus.Warnln(addr, "Fallback DialUDP err:", err)
		return
	}
	logrus.Warnln(addr, "Fallback from", fbconn.LocalAddr(), "to", fbconn.RemoteAddr())
	defer fbconn.Close()
	payload.V(func(b []byte) {
		_, err = fbconn.Write(b)
		if err != nil {
			logrus.Warnln(addr, "Write to fallback err:", err)
			return
		}
	})
	if err != nil {
		return
	}
	_ = fbconn.SetReadDeadline(time.Now().Add(time.Second * 4))
	pbuf.NewBytes(4096).V(func(b []byte) {
		var (
			n       int
			srvaddr *net.UDPAddr
		)
		for {
			n, srvaddr, err = fbconn.ReadFromUDP(b)
			if err != nil {
				logrus.Warnln(addr, "Read from fallback err:", err)
				return
			}
			if !srvaddr.IP.Equal(fallback.IP) || srvaddr.Port != fallback.Port {
				logrus.Warnln(addr, "Read expect fallback addr but got", srvaddr)
				err = errors.New("wrong endpoint")
				continue
			}
			break
		}
		if err == nil {
			_, err = conn.WriteToUDP(b[:n], addr)
			if err != nil {
				return
			}
			logrus.Debugln("Write fallback response to", addr)
		}
	})
}

// lockfree is spin update
func lockfree() uint8 {
	old := atomic.LoadUintptr(&freeconn)
	for i := uint8(0); i < uint8(unsafe.Sizeof(uintptr(0)))*8; i++ {
		for old&(1<<i) == 0 { // is free
			ok := atomic.CompareAndSwapUintptr(&freeconn, old, old|(1<<i))
			if ok {
				return i
			}
			// update latest
			old = atomic.LoadUintptr(&freeconn)
		}
	}
	return math.MaxUint8
}

// releasefree is spin update
func releasefree(i uint8) {
	old := atomic.LoadUintptr(&freeconn)
	for old&(1<<i) != 0 { // is not free
		ok := atomic.CompareAndSwapUintptr(&freeconn, old, old&^(1<<i))
		if ok {
			return
		}
		// update latest
		old = atomic.LoadUintptr(&freeconn)
	}
}

func dialtls(cnt uint8, ctx context.Context) (net.Conn, error) {
	conn := tlsconnCache.Get(cnt)
	if conn != nil {
		logrus.Debugln("Lock", cnt, "get cached tls conn to", conn.RemoteAddr())
		return conn, nil
	}
	// dummy nw and addr
	conn, err := dns.DefaultResolver.Dial(ctx, "", "")
	if err != nil {
		return nil, err
	}
	tlsconnCache.Set(cnt, conn)
	logrus.Debugln("Lock", cnt, "set new tls conn to", conn.RemoteAddr())
	return conn, nil
}
