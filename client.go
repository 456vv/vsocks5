package vsocks5

import (
	"errors"
	"net"
	"time"
)

type Client struct {
	Server   string
	UserName string
	Password string
	DialTCP func(net string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error)
	// On cmd UDP, let server control the tcp and udp connection relationship
	tcpConn       *net.TCPConn
	udpConn       *net.UDPConn
	remoteAddress net.Addr			//udp used
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
	
	if err := c.negotiate(la); err != nil {
		return nil, err
	}
	
	if network == "tcp" {
		
		if c.remoteAddress == nil {
			c.remoteAddress, err = net.ResolveTCPAddr("tcp", dst)
			if err != nil {
				return nil, err
			}
		}
		
		a, h, p, err := parseAddress(dst)
		if err != nil {
			return nil, err
		}
		
		r := newRequestTCP(CmdConnect, a, h, p)
		if _, err := c.request(r); err != nil {
			return nil, err
		}
		
		return &c, nil
	}else if network == "udp" {
		
		if c.remoteAddress == nil {
			c.remoteAddress, err = net.ResolveUDPAddr("udp", dst)
			if err != nil {
				return nil, err
			}
		}
		
		laddr := &net.UDPAddr{
			IP:   c.tcpConn.LocalAddr().(*net.TCPAddr).IP,
			Port: c.tcpConn.LocalAddr().(*net.TCPAddr).Port,
			Zone: c.tcpConn.LocalAddr().(*net.TCPAddr).Zone,
		}
		
		a, h, p, err := parseAddress(laddr.String())
		if err != nil {
			return nil, err
		}
		
		//告诉服务器，我发起的UDP本地地址
		r := newRequestTCP(CmdUDP, a, h, p)
		rp, err := c.request(r)
		if err != nil {
			return nil, err
		}
		
		//服务给的端口地址
		raddr, err := net.ResolveUDPAddr("udp", rp.Address())
		if err != nil {
			return nil, err
		}
		
		c.udpConn, err = net.DialUDP("udp", laddr, raddr)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
	return nil, errors.New("unsupport network")
}

func (c *Client) Read(b []byte) (int, error) {
	if c.udpConn == nil {
		return c.tcpConn.Read(b)
	}
	n, err := c.udpConn.Read(b)
	if err != nil {
		return 0, err
	}
	d, err := readRequestUDP(b[0:n])
	if err != nil {
		return 0, err
	}
	n = copy(b, d.Data)
	return n, nil
}

func (c *Client) Write(b []byte) (int, error) {
	if c.udpConn == nil {
		return c.tcpConn.Write(b)
	}
	a, h, p, err := parseAddress(c.remoteAddress.String())
	if err != nil {
		return 0, err
	}
	
	d := newReplyUDP(a, h, p, b)
	b1 := d.Bytes()
	n, err := c.udpConn.Write(b1)
	if err != nil {
		return 0, err
	}
	if len(b1) != n {
		return 0, errors.New("not write full")
	}
	return len(b), nil
}

func (c *Client) Close() error {
	if c.udpConn == nil {
		return c.tcpConn.Close()
	}
	if c.tcpConn != nil {
		c.tcpConn.Close()
	}
	return c.udpConn.Close()
}

func (c *Client) LocalAddr() net.Addr {
	if c.udpConn == nil {
		return c.tcpConn.LocalAddr()
	}
	return c.udpConn.LocalAddr()
}

func (c *Client) RemoteAddr() net.Addr {
	return c.remoteAddress
}

func (c *Client) SetDeadline(t time.Time) error {
	if c.udpConn == nil {
		return c.tcpConn.SetDeadline(t)
	}
	return c.udpConn.SetDeadline(t)
}

func (c *Client) SetReadDeadline(t time.Time) error {
	if c.udpConn == nil {
		return c.tcpConn.SetReadDeadline(t)
	}
	return c.udpConn.SetReadDeadline(t)
}

func (c *Client) SetWriteDeadline(t time.Time) error {
	if c.udpConn == nil {
		return c.tcpConn.SetWriteDeadline(t)
	}
	return c.udpConn.SetWriteDeadline(t)
}

func (c *Client) negotiate(laddr *net.TCPAddr) error {
	raddr, err := net.ResolveTCPAddr("tcp", c.Server)
	if err != nil {
		return err
	}
	if c.DialTCP != nil {
		c.tcpConn, err = c.DialTCP("tcp", laddr, raddr)
	}else{
		c.tcpConn, err = net.DialTCP("tcp", laddr, raddr)
	}
	if err != nil {
		return err
	}
	
	m := MethodNone
	if c.UserName != "" {
		m = MethodUsernamePassword
	}
	rq := newNegotiateWriteRequest([]byte{m})
	if _, err := rq.WriteTo(c.tcpConn); err != nil {
		return err
	}
	
	rp, err := negotiateReadReply(c.tcpConn)
	if err != nil {
		return err
	}
	if rp.Method != m {
		return errors.New("Unsupport method")
	}
	
	if m == MethodUsernamePassword {
		urq := newNegotiateAuthRequest([]byte(c.UserName), []byte(c.Password))
		if _, err := urq.WriteTo(c.tcpConn); err != nil {
			return err
		}
		
		urp, err := negotiateAuthReply(c.tcpConn)
		if err != nil {
			return err
		}
		
		if urp.Status != UserPassStatusSuccess {
			return ErrUserPassAuth
		}
	}
	return nil
}

func (c *Client) request(r *RequestTCP) (*ReplyTCP, error) {
	if _, err := r.WriteTo(c.tcpConn); err != nil {
		return nil, err
	}
	rp, err := readReplyTCP(c.tcpConn)
	if err != nil {
		return nil, err
	}
	if rp.Rep != RepSuccess {
		return nil, errors.New("Host unreachable")
	}
	return rp, nil
}
