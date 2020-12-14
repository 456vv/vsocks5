package vsocks5

import (
	"io"
	"encoding/binary"
	"bytes"
	"net"
	"strconv"
	"context"
)

type NegotiationRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1-255 bytes
}
func (r *NegotiationRequest) WriteTo(w io.Writer) (int64, error) {
	b := []byte{r.Ver, r.NMethods}
	b = append(b, r.Methods...)
	n, err := w.Write(b)
	return int64(n), err
}

type NegotiationReply struct {
	Ver    byte
	Method byte
}
func (r *NegotiationReply) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write([]byte{r.Ver, r.Method})
	return int64(n), err
}

type NegotiationRequestAuth struct {
	Ver    byte
	Ulen   byte
	Uname  []byte // 1-255 bytes
	Plen   byte
	Passwd []byte // 1-255 bytes
}
func (r *NegotiationRequestAuth) WriteTo(w io.Writer) (int64, error) {
	b := []byte{r.Ver, r.Ulen}
	b = append(b, r.Uname...)
	b = append(b, r.Plen)
	b = append(b, r.Passwd...)
	n, err := w.Write(b)
	return int64(n), err
}
type NegotiationReplyAuth struct {
	Ver    byte
	Status byte
}
func (r *NegotiationReplyAuth) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write([]byte{r.Ver, r.Status})
	return int64(n), err
}

type RequestTCP struct {
	Ver     byte
	Cmd     byte
	Rsv     byte // 0x00
	Atyp    byte
	DstAddr []byte
	DstPort []byte // 2 bytes
}
func (r *RequestTCP) replyError(rep byte, w io.Writer) error {
	var p *ReplyTCP
	if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
		p = newReplyTCP(rep, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	} else {
		p = newReplyTCP(rep, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
	}
	if _, err :=p.WriteTo(w); err != nil {
		return err
	}
	return nil
}
func (r *RequestTCP) Address() string {
	var s string
	if r.Atyp == ATYPDomain {
		s = bytes.NewBuffer(r.DstAddr[1:]).String()
	} else {
		s = net.IP(r.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.DstPort)))
	return net.JoinHostPort(s, p)
}
func (r *RequestTCP) RemoteConnect(dial *Dialer, w io.Writer) (rc net.Conn, err error) {
	
	if dial.Dial != nil {
		rc, err = dial.Dial("tcp", r.Address())
	}else if dial.DialContext != nil {
		rc, err = dial.DialContext(context.Background(), "tcp", r.Address())
	}else{
		rc, err = net.Dial("tcp", r.Address())
	}
	if err != nil {
		if e := r.replyError(RepHostUnreachable, w); e != nil {
			return nil, e
		}
		return nil, err
	}
	
	a, addr, port, err := parseAddress(rc.LocalAddr().String())
	if err != nil {
		if e := r.replyError(RepHostUnreachable, w); e != nil {
			return nil, e
		}
		return nil, err
	}
	p := newReplyTCP(RepSuccess, a, addr, port)
	if _, err := p.WriteTo(w); err != nil {
		return nil, err
	}

	return rc, nil
}
func (r *RequestTCP) UDP(clientTCPConn net.Conn, proxyAddr *net.UDPAddr) (clientUDPAddr *net.UDPAddr, err error) {
	if bytes.Compare(r.DstPort, []byte{0x00, 0x00}) == 0 {
		// 如果请求的主机/端口都是零，那么中继应该只使用发送请求的主机/端口。
		// https://stackoverflow.com/questions/62283351/how-to-use-socks-5-proxy-with-tidudpclient-properly
		clientUDPAddr, err = net.ResolveUDPAddr("udp", clientTCPConn.RemoteAddr().String())
	} else {
		clientUDPAddr, err = net.ResolveUDPAddr("udp", r.Address())
	}
	if err != nil {
		if e := r.replyError(RepHostUnreachable, clientTCPConn); e != nil {
			return nil, e
		}
		return nil, err
	}
	
	a, addr, port, err := parseAddress(proxyAddr.String())
	if err != nil {
		if e := r.replyError(RepHostUnreachable, clientTCPConn); e != nil {
			return nil, e
		}
		return nil, err
	}

	p := newReplyTCP(RepSuccess, a, addr, port)
	if _, err := p.WriteTo(clientTCPConn); err != nil {
		return nil, err
	}
	return clientUDPAddr, nil
}
func (r *RequestTCP) WriteTo(w io.Writer) (int64, error) {
	b := []byte{r.Ver, r.Cmd, r.Rsv, r.Atyp}
	b = append(b, r.DstAddr...)
	b = append(b, r.DstPort...)
	n, err := w.Write(b)
	return int64(n), err
}

type ReplyTCP struct {
	Ver  byte
	Rep  byte
	Rsv  byte // 0x00
	Atyp byte
	// CONNECT socks server's address which used to connect to dst addr
	// BIND ...
	// UDP socks server's address which used to connect to dst addr
	BndAddr []byte
	// CONNECT socks server's port which used to connect to dst addr
	// BIND ...
	// UDP socks server's port which used to connect to dst addr
	BndPort []byte // 2 bytes
}
func (r *ReplyTCP) WriteTo(w io.Writer) (int64, error) {
	b := []byte{r.Ver, r.Rep, r.Rsv, r.Atyp}
	b = append(b, r.BndAddr...)
	b = append(b, r.BndPort...)
	n, err := w.Write(b)
	return int64(n), err
}
func (r *ReplyTCP) Address() string {
	var s string
	if r.Atyp == ATYPDomain {
		s = bytes.NewBuffer(r.BndAddr[1:]).String()
	} else {
		s = net.IP(r.BndAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.BndPort)))
	return net.JoinHostPort(s, p)
}


// 数据报文是UDP包
type DatagramUDP struct {
	Rsv     []byte // 0x00 0x00
	Frag    byte
	Atyp    byte
	DstAddr []byte
	DstPort []byte // 2 bytes
	Data    []byte
}
// Bytes return []byte
func (d *DatagramUDP) Bytes() []byte {
	b := make([]byte, 0)
	b = append(b, d.Rsv...)
	b = append(b, d.Frag)
	b = append(b, d.Atyp)
	b = append(b, d.DstAddr...)
	b = append(b, d.DstPort...)
	b = append(b, d.Data...)
	return b
}
func (d *DatagramUDP) Address() string {
	var s string
	if d.Atyp == ATYPDomain {
		s = bytes.NewBuffer(d.DstAddr[1:]).String()
	} else {
		s = net.IP(d.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(d.DstPort)))
	return net.JoinHostPort(s, p)
}
