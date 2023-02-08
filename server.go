package vsocks5

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/456vv/vmap/v2"
)

const (
	socks5Version = uint8(5)
)

type Server struct {
	Auth      func(username, password string) bool
	Supported Cmd
	Addr      string
	listenTCP *net.TCPListener
	listenUDP *net.UDPConn
	Handle    Handler
	ErrorLog  *log.Logger // 日志
	Method    byte
}

func (T *Server) ListenAndServe() error {
	go T.ServerUDP()
	return T.ServerTCP()
}

func (T *Server) Close() error {
	if T.listenTCP != nil {
		T.listenTCP.Close()
	}
	if T.listenUDP != nil {
		T.listenUDP.Close()
	}
	return nil
}

func (T *Server) ServerTCP() error {
	if T.Addr == "" {
		return ErrEmptyAddr
	}
	if T.Handle == nil {
		return ErrHandler
	}

	var err error
	taddr, err := net.ResolveTCPAddr("tcp", T.Addr)
	if err != nil {
		return err
	}

	T.listenTCP, err = net.ListenTCP("tcp", taddr)
	if err != nil {
		return err
	}
	defer T.listenTCP.Close()
	T.Addr = T.listenTCP.Addr().String()

	var (
		tempDelay time.Duration
		ok        bool
	)
	for {
		conn, err := T.listenTCP.AcceptTCP()
		if err != nil {
			if tempDelay, ok = temporaryError(err, tempDelay, time.Second); ok {
				continue
			}
			return err
		}
		tempDelay = 0
		go T.serveConnTCP(conn)
	}
}

func (T *Server) serveConnTCP(conn net.Conn) error {
	defer conn.Close()

	if err := T.negotiate(conn); err != nil {
		T.logf(err.Error())
		return err
	}
	r, err := T.readRequest(conn)
	if err != nil {
		T.logf(err.Error())
		return err
	}
	if err := T.Handle.TCP(conn, r); err != nil {
		T.logf(err.Error())
		return err
	}
	return nil
}

func (T *Server) negotiate(rw io.ReadWriter) error {
	rq, err := ReadNegotiateMethodRequest(rw)
	if err != nil {
		return err
	}
	var got bool
	for _, m := range rq.Methods {
		if m == T.Method {
			got = true
		}
	}

	if !got {
		rp := NewNegotiateMethodReply(MethodUnsupportAll)
		if _, err := rp.WriteTo(rw); err != nil {
			return err
		}
	}
	rp := NewNegotiateMethodReply(T.Method)
	if _, err := rp.WriteTo(rw); err != nil {
		return err
	}

	if T.Method == MethodUsernamePassword {
		urq, err := ReadNegotiateAuthRequest(rw)
		if err != nil {
			return err
		}
		if T.Auth != nil && !T.Auth(string(urq.Uname), string(urq.Passwd)) {
			urp := NewNegotiateAuthReply(UserPassStatusFailure)
			if _, err := urp.WriteTo(rw); err != nil {
				return err
			}
			return ErrUserPassAuth
		}
		urp := NewNegotiateAuthReply(UserPassStatusSuccess)
		if _, err := urp.WriteTo(rw); err != nil {
			return err
		}
	}
	return nil
}

func (T *Server) readRequest(rw io.ReadWriter) (*RequestTCP, error) {
	r, err := ReadRequestTCP(rw)
	if err != nil {
		return nil, err
	}
	var supported bool
	for _, c := range T.Supported {
		if r.Cmd == c {
			supported = true
			break
		}
	}
	if !supported {
		if e := r.ReplyError(RepCommandNotSupported, rw); e != nil {
			return nil, e
		}
		return nil, ErrUnsupportCmd
	}
	return r, nil
}

func (T *Server) ServerUDP() error {
	if T.Addr == "" {
		return ErrEmptyAddr
	}
	if T.Handle == nil {
		return ErrHandler
	}

	var err error
	uaddr, err := net.ResolveUDPAddr("udp", T.Addr)
	if err != nil {
		return err
	}

	T.listenUDP, err = net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}

	defer T.listenUDP.Close()

	b := make([]byte, 65507)
	for {
		n, addr, err := T.listenUDP.ReadFromUDP(b)
		if err != nil {
			return err
		}
		go T.serveConnUDP(addr, b[0:n])
	}
}

func (T *Server) serveConnUDP(cAddr *net.UDPAddr, b []byte) error {
	d, err := ReadRequestUDP(b)
	if err != nil {
		T.logf(err.Error())
		return err
	}
	if d.Frag != 0x00 {
		T.logf("Ignore frag: %d", d.Frag)
		return err
	}
	if err := T.Handle.UDP(T.listenUDP, cAddr, d); err != nil {
		T.logf(err.Error())
		return err
	}
	return nil
}

func (T *Server) logf(format string, v ...interface{}) error {
	err := fmt.Errorf(format+"\n", v...)
	if T.ErrorLog != nil {
		T.ErrorLog.Output(2, err.Error())
	}
	return err
}

type Dialer struct {
	Dial        func(network, address string) (net.Conn, error)
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}
type Handler interface {
	TCP(net.Conn, *RequestTCP) error
	UDP(*net.UDPConn, *net.UDPAddr, *DatagramUDP) error
}

type DefaultHandle struct {
	Dialer
	BuffSize      int
	associatedUDP vmap.Map
	udpExchange   vmap.Map
}

func (T *DefaultHandle) TCP(cconn net.Conn, r *RequestTCP) error {
	if r.Cmd == CmdConnect {
		rc, err := r.RemoteConnect(&T.Dialer, cconn)
		if err != nil {
			return err
		}
		defer rc.Close()

		buffsize := T.BuffSize
		if buffsize == 0 {
			buffsize = BuffSize
		}
		go copyData(cconn, rc, buffsize)
		_, err = copyData(rc, cconn, buffsize)
		if err == io.EOF {
			return nil
		}
		return err
	}
	if r.Cmd == CmdUDP {
		// cconn.LocalAddr 就是代理服务开启监听的TCP/UDP地址
		proxyAddr := new(net.UDPAddr)
		if tcpAddr, ok := cconn.LocalAddr().(*net.TCPAddr); ok {
			proxyAddr.IP = tcpAddr.IP
			proxyAddr.Port = tcpAddr.Port
			proxyAddr.Zone = tcpAddr.Zone
		}

		// clientUDPAddr 客户端会使用此地址发起UDP请求
		clientUDPAddr, err := r.UDP(cconn, proxyAddr)
		if err != nil {
			return err
		}

		allowFlag := clientUDPAddr.String()
		// 防止多条连接发送同样请求
		if T.associatedUDP.Has(allowFlag) {
			cconn.Close()
			return nil
		}

		// 记录地址，允许访问
		noticeClose := make(chan struct{})
		T.associatedUDP.Set(allowFlag, noticeClose)
		defer func() {
			T.associatedUDP.Del(allowFlag)
			time.Sleep(time.Millisecond * 50)
			close(noticeClose)
		}()
		io.Copy(ioutil.Discard, cconn)
		return nil
	}
	return ErrUnsupportCmd
}

func (T *DefaultHandle) UDP(proxyUDP *net.UDPConn, cAddr *net.UDPAddr, d *DatagramUDP) error {
	// 允许访问
	src := cAddr.String()
	ch, ok := T.associatedUDP.GetHas(src)
	if !ok {
		return fmt.Errorf("this udp address %s is not associated with tcp", src)
	}

	dst := d.Address()
	var e *udpExchange
	ie, ok := T.udpExchange.GetHas(src + dst)
	if ok {
		e = ie.(*udpExchange)
		if err := T.sendUDP(e, d.Data); err != nil {
			e.remoteConn.Close()
			return err
		}
		return nil
	}

	var laddr *net.UDPAddr = nil
	raddr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return err
	}

	rconn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return err
	}
	defer rconn.Close()

	e = &udpExchange{
		noticeClose: ch.(chan struct{}),
		serverConn:  proxyUDP,
		clientAddr:  cAddr,
		remoteConn:  rconn,
	}
	T.udpExchange.Set(src+dst, e)
	defer T.udpExchange.Del(src + dst)

	if err := T.sendUDP(e, d.Data); err != nil {
		rconn.Close()
		return err
	}

	return T.readUDP(e, dst)
}

func (T *DefaultHandle) sendUDP(e *udpExchange, data []byte) error {
	select {
	case <-e.noticeClose:
		return ErrTCPConnClose
	default:
		_, err := e.remoteConn.Write(data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (T *DefaultHandle) readUDP(e *udpExchange, dst string) error {
	var b [65507]byte
	for {
		select {
		case <-e.noticeClose:
			return ErrTCPConnClose
		default:
			n, err := e.remoteConn.Read(b[:])
			if err != nil {
				return err
			}

			a, addr, port, err := ParseAddress(dst)
			if err != nil {
				return err
			}

			d1 := NewRequestUDP(a, addr, port, b[:n])
			if _, err := e.serverConn.WriteToUDP(d1.Bytes(), e.clientAddr); err != nil {
				return err
			}
		}
	}
}

type udpExchange struct {
	noticeClose chan struct{}
	serverConn  *net.UDPConn
	clientAddr  *net.UDPAddr
	remoteConn  *net.UDPConn
}
