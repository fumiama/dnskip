package main

import (
	"context"
	"encoding/binary"
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
)

func main() {
	iphost := flag.String("l", "127.0.0.1:5345", "listen DNS UDP port")
	frag := flag.Uint("frag", 3, "TLS first fragemt size")
	flag.Parse()

	if frag != nil {
		terasu.DefaultFirstFragmentLen = uint8(*frag)
	}

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
	defer releasefree(cnt)
	logrus.Debugln(addr, "Run on lock", cnt)

	loopcnt := 0
REDAIL:
	tlsconn, err := dialtls(cnt)
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
	if err != nil {
		logrus.Warnln(addr, "Proxy to DNS server err:", err)
		tlsconnCache.Delete(cnt)
		loopcnt++
		if loopcnt < 3 {
			goto REDAIL
		}
		return
	}
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

func dialtls(cnt uint8) (net.Conn, error) {
	conn := tlsconnCache.Get(cnt)
	if conn != nil {
		logrus.Debugln("Lock", cnt, "get cached tls conn to", conn.RemoteAddr())
		return conn, nil
	}
	// dummy nw and addr
	conn, err := dns.DefaultResolver.Dial(context.Background(), "", "")
	if err != nil {
		return nil, err
	}
	tlsconnCache.Set(cnt, conn)
	logrus.Debugln("Lock", cnt, "set new tls conn to", conn.RemoteAddr())
	return conn, nil
}
