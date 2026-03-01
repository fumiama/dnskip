package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"math"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/fumiama/orbyte/pbuf"
	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/dialer"
	"github.com/fumiama/terasu/dns"
	_ "github.com/fumiama/terasu/ext"
	"github.com/fumiama/terasu/ip"
	"github.com/sirupsen/logrus"
)

var (
	fallback *net.UDPAddr
	forcefb  bool
	timeout  uint
	keept    uint
)

func main() {
	iphost := flag.String("l", "127.0.0.1:5345", "listen DNS UDP port")
	fbsrv := flag.String("fb", "127.0.0.1:53", "fallback to DNS UDP port")
	debug := flag.Bool("d", false, "show debug log")
	flag.UintVar(&timeout, "to", 4, "dial timeout in sec, >= 1")
	flag.UintVar(&keept, "kt", 4, "tls conn keep time in min, >= 1")
	flag.BoolVar(&forcefb, "ffb", false, "force using fallback")
	flag.BoolVar(&ip.IsIPv6Available, "6", false, "use ipv6 servers")
	frag := flag.Uint("frag", 4, "TLS first fragemt size (0 to disable)")
	sz := flag.Uint("sz", 2, "tls conn pool size")
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

	if *sz <= 0 || *sz > 32 {
		logrus.Fatal("-sz must between [1, 32]")
	}
	remoconn = make([]*tls.Conn, *sz)

	if timeout <= 0 {
		timeout = 1
	}

	if keept <= 0 {
		keept = 1
	}

	go func() {
		t := time.NewTicker(time.Second * 10)
		defer t.Stop()
		c := 0
		for range t.C {
			c++
			o, i := pbuf.CountItems()
			logrus.Debugln("Orbyte pbuf outside:", o, "inside:", i)
			if c%8 == 0 {
				runtime.GC()
			}
		}
	}()

	dialer.SetDefaultTimeout(time.Second * time.Duration(timeout))

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
		cl      func()
		tlsconn *tls.Conn
		loopcnt = 0
		ctx     context.Context
		cancel  context.CancelFunc
	)

	if forcefb {
		goto FALLBACK
	}

	defer releasefree(cnt)
	logrus.Debugln(addr, "Run thread", cnt)

REDAIL:
	ctx, cancel = context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
	defer cancel()
	tlsconn, cl, err = dialtls(cnt, ctx)
	if err != nil {
		logrus.Warnln(addr, "Dial DNS server err:", err)
		return
	}
	logrus.Debugln(addr, "Dial to DNS server", tlsconn.RemoteAddr())

	payload.V(func(b []byte) {
		defer cl()

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
	marktlsfail(cnt)
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

var (
	freeconn = uint32(0)
)

// lockfree is spin update
func lockfree() uint8 {
	old := atomic.LoadUint32(&freeconn)
	for i := uint8(0); i < uint8(unsafe.Sizeof(freeconn))*8; i++ {
		for old&(1<<i) == 0 { // is free
			ok := atomic.CompareAndSwapUint32(&freeconn, old, old|(1<<i))
			if ok {
				return i
			}
			// update latest
			old = atomic.LoadUint32(&freeconn)
		}
	}
	return math.MaxUint8
}

// releasefree is spin update
func releasefree(i uint8) {
	old := atomic.LoadUint32(&freeconn)
	for old&(1<<i) != 0 { // is not free
		ok := atomic.CompareAndSwapUint32(&freeconn, old, old&^(1<<i))
		if ok {
			return
		}
		// update latest
		old = atomic.LoadUint32(&freeconn)
	}
	logrus.Debugln("Free thread", i)
}

var (
	remoconn []*tls.Conn
	connmu   sync.Mutex
)

func dialtls(cnt uint8, ctx context.Context) (*tls.Conn, func(), error) {
	idx := cnt % uint8(len(remoconn))
	conn := (*tls.Conn)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&remoconn[idx]))))
	if conn != nil {
		logrus.Debugln("Thread", cnt, "idx", idx, "get cached tls conn to", conn.RemoteAddr())
		connmu.Lock()
		return conn, connmu.Unlock, nil
	}
	// slow path
	connmu.Lock()
	conn = (*tls.Conn)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&remoconn[idx]))))
	if conn != nil {
		logrus.Debugln("Thread", cnt, "idx", idx, "slowly get cached tls conn to", conn.RemoteAddr())
		return conn, connmu.Unlock, nil
	}
	// dummy nw and addr
	connintf, err := dns.DefaultResolver.Dial(ctx, "", "")
	if err != nil {
		connmu.Unlock()
		return nil, nil, err
	}
	conn = connintf.(*tls.Conn)
	atomic.StorePointer(
		(*unsafe.Pointer)(unsafe.Pointer(&remoconn[idx])),
		unsafe.Pointer(conn),
	)
	logrus.Infoln("Thread", cnt, "idx", idx, "set new tls conn to", conn.RemoteAddr())
	time.AfterFunc(time.Minute*time.Duration(keept), func() { marktlsfail(cnt) })
	return conn, connmu.Unlock, nil
}

func marktlsfail(cnt uint8) {
	idx := cnt % uint8(len(remoconn))
	logrus.Infoln("Thread", cnt, "idx", idx, "reset conn to nil")
	oldConn := (*tls.Conn)(atomic.SwapPointer(
		(*unsafe.Pointer)(unsafe.Pointer(&remoconn[idx])),
		unsafe.Pointer(nil),
	))
	if oldConn != nil {
		logrus.Infoln("Thread", cnt, "idx", idx, "close conn to", oldConn.RemoteAddr())
		_ = oldConn.Close()
	}
}
