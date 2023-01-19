package vsocks5

import (
	"errors"
	"net"
	"time"
)

type clientConn struct {
	sconn         net.Conn
	conn          net.Conn
	istcp         bool
	remoteAddress net.Addr // udp used
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	if n, err = c.conn.Read(b); err != nil || c.istcp {
		return
	}
	d, err := ReadRequestUDP(b[0:n])
	if err != nil {
		return 0, err
	}
	n = copy(b, d.Data)
	return n, nil
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if c.istcp {
		return c.conn.Write(b)
	}

	a, h, p, err := ParseAddress(c.remoteAddress.String())
	if err != nil {
		return 0, err
	}

	d := NewRequestUDP(a, h, p, b)
	b1 := d.Bytes()
	if n, err = c.conn.Write(b1); err != nil {
		return 0, err
	}
	if len(b1) != n {
		return 0, errors.New("not write full")
	}
	return len(b), nil
}

func (c *clientConn) Close() error {
	if !c.istcp {
		// 使用udp代理后，需要关闭原有的tcp连接
		c.sconn.Close()
	}
	return c.conn.Close()
}

func (c *clientConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.remoteAddress
}

func (c *clientConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type Client struct {
	Server   string
	Username string
	Password string
	DialTCP  func(network string, laddr, raddr *net.TCPAddr) (net.Conn, error)
}

func (c *Client) dial(laddr *net.TCPAddr) (conn net.Conn, err error) {
	raddr, err := net.ResolveTCPAddr("tcp", c.Server)
	if err != nil {
		return nil, err
	}
	if c.DialTCP != nil {
		return c.DialTCP("tcp", laddr, raddr)
	}
	return net.DialTCP("tcp", laddr, raddr)
}

func (c *Client) Dial(network, addr string) (net.Conn, error) {
	return c.DialWithLocalAddr(network, "", addr)
}

func (c Client) DialWithLocalAddr(network, src, dst string) (net.Conn, error) {
	var err error

	var la *net.TCPAddr
	if src != "" {
		la, err = net.ResolveTCPAddr("tcp", src)
		if err != nil {
			return nil, err
		}
	}
	conn, err := c.dial(la)
	if err != nil {
		return nil, err
	}

	nt, ok := conn.(*Negotiate)
	if !ok || !nt.done {
		if err = negotiate(conn, c.Username, c.Password); err != nil {
			return nil, err
		}
	}
	raddr, err := net.ResolveTCPAddr("tcp", dst)
	if err != nil {
		return nil, err
	}
	switch network {
	case "tcp":
		c.requestTCP(conn, dst)
		return &clientConn{conn: conn, istcp: true, remoteAddress: raddr}, nil
	case "udp":
		udpConn, err := c.requestUDP(conn, dst)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return &clientConn{sconn: conn, conn: udpConn, remoteAddress: raddr}, nil
	}
	return nil, errors.New("unsupport network")
}

func (c *Client) requestTCP(conn net.Conn, dst string) (*ReplyTCP, error) {
	a, h, p, err := ParseAddress(dst)
	if err != nil {
		return nil, err
	}

	r := NewRequestTCP(CmdConnect, a, h, p)
	return c.request(conn, r)
}

func (c *Client) requestUDP(conn net.Conn, dst string) (net.Conn, error) {
	// 告诉代理服务器，我使用这个地址端口向代理服务器发起UDP请求
	laddr := &net.UDPAddr{
		IP:   conn.LocalAddr().(*net.TCPAddr).IP,
		Port: conn.LocalAddr().(*net.TCPAddr).Port,
		Zone: conn.LocalAddr().(*net.TCPAddr).Zone,
	}
	a, h, p, err := ParseAddress(laddr.String())
	if err != nil {
		return nil, err
	}
	r := NewRequestTCP(CmdUDP, a, h, p)
	rp, err := c.request(conn, r)
	if err != nil {
		return nil, err
	}

	// 服务给监听的端口地址
	raddr, err := net.ResolveUDPAddr("udp", rp.Address())
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", laddr, raddr)
}

func (c *Client) request(conn net.Conn, r *RequestTCP) (*ReplyTCP, error) {
	if _, err := r.WriteTo(conn); err != nil {
		return nil, err
	}
	rp, err := ReadReplyTCP(conn)
	if err != nil {
		return nil, err
	}
	if rp.Rep != RepSuccess {
		return nil, errors.New("host unreachable")
	}
	return rp, nil
}

type Negotiate struct {
	net.Conn
	done bool
}

// 验证账号
func (T *Negotiate) Auth(username, password string) error {
	T.done = true
	return negotiate(T, username, password)
}

func negotiate(conn net.Conn, username, passwod string) error {
	m := MethodNone
	if username != "" {
		m = MethodUsernamePassword
	}
	rq := NewNegotiateMethodRequest([]byte{m})
	if _, err := rq.WriteTo(conn); err != nil {
		return err
	}
	rp, err := ReadNegotiateMethodReply(conn)
	if err != nil {
		return err
	}
	if rp.Method != m {
		return errors.New("unsupport method")
	}
	if m == MethodUsernamePassword {
		urq := NewNegotiateAuthRequest([]byte(username), []byte(passwod))
		if _, err := urq.WriteTo(conn); err != nil {
			return err
		}

		urp, err := ReadNegotiateAuthReply(conn)
		if err != nil {
			return err
		}

		if urp.Status != UserPassStatusSuccess {
			return ErrUserPassAuth
		}
	}
	return nil
}
