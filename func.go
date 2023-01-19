package vsocks5

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

// client
//
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1 to 255 |
//	+----+----------+----------+
func NewNegotiateMethodRequest(methods []byte) *NegotiationRequest {
	return &NegotiationRequest{
		Ver:      Ver,
		NMethods: byte(len(methods)),
		Methods:  methods,
	}
}

// server
//
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1 to 255 |
//	+----+----------+----------+
func ReadNegotiateMethodRequest(r io.Reader) (*NegotiationRequest, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}

	if bb[0] != Ver {
		return nil, ErrVersion
	}
	if bb[1] == 0 {
		return nil, ErrBadRequest
	}
	ms := make([]byte, int(bb[1]))
	if _, err := io.ReadFull(r, ms); err != nil {
		return nil, err
	}
	return &NegotiationRequest{
		Ver:      bb[0],
		NMethods: bb[1],
		Methods:  ms,
	}, nil
}

// server
//
//	+----+--------+
//	|VER | METHOD |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
func NewNegotiateMethodReply(method byte) *NegotiationReply {
	return &NegotiationReply{
		Ver:    Ver,
		Method: method,
	}
}

// client
//
//	+----+--------+
//	|VER | METHOD |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
func ReadNegotiateMethodReply(r io.Reader) (*NegotiationReply, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}
	return &NegotiationReply{
		Ver:    bb[0],
		Method: bb[1],
	}, nil
}

// client
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
func NewNegotiateAuthRequest(username []byte, password []byte) *NegotiationRequestAuth {
	return &NegotiationRequestAuth{
		Ver:    UserPassVer,
		Ulen:   byte(len(username)),
		Uname:  username,
		Plen:   byte(len(password)),
		Passwd: password,
	}
}

// server
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
func ReadNegotiateAuthRequest(r io.Reader) (*NegotiationRequestAuth, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != UserPassVer {
		return nil, ErrUserPassVersion
	}
	if bb[1] == 0 {
		return nil, ErrBadRequest
	}
	ub := make([]byte, int(bb[1])+1)
	if _, err := io.ReadFull(r, ub); err != nil {
		return nil, err
	}
	if ub[int(bb[1])] == 0 {
		return nil, ErrBadRequest
	}
	p := make([]byte, int(ub[int(bb[1])]))
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return &NegotiationRequestAuth{
		Ver:    bb[0],
		Ulen:   bb[1],
		Uname:  ub[:int(bb[1])],
		Plen:   ub[int(bb[1])],
		Passwd: p,
	}, nil
}

// server
//
//	+----+--------+
//	|VER | STATUS |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
func NewNegotiateAuthReply(status byte) *NegotiationReplyAuth {
	return &NegotiationReplyAuth{
		Ver:    UserPassVer,
		Status: status,
	}
}

// client
//
//	+----+--------+
//	|VER | STATUS |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
func ReadNegotiateAuthReply(r io.Reader) (*NegotiationReplyAuth, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != UserPassVer {
		return nil, ErrUserPassVersion
	}
	return &NegotiationReplyAuth{
		Ver:    bb[0],
		Status: bb[1],
	}, nil
}

// client
//
//	+----+-----+-------+------+----------+----------+
//	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
func NewRequestTCP(cmd byte, atyp byte, dstaddr []byte, dstport []byte) *RequestTCP {
	if atyp == ATYPDomain {
		dstaddr = append([]byte{byte(len(dstaddr))}, dstaddr...)
	}
	return &RequestTCP{
		Ver:     Ver,
		Cmd:     cmd,
		Rsv:     0x00,
		Atyp:    atyp,
		DstAddr: dstaddr,
		DstPort: dstport,
	}
}

// server
//
//	+----+-----+-------+------+----------+----------+
//	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
func ReadRequestTCP(r io.Reader) (*RequestTCP, error) {
	bb := make([]byte, 4)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}
	var addr []byte
	switch bb[3] {
	case ATYPIPv4:
		addr = make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	case ATYPIPv6:
		addr = make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	case ATYPDomain:
		dal := make([]byte, 1)
		if _, err := io.ReadFull(r, dal); err != nil {
			return nil, err
		}
		if dal[0] == 0 {
			return nil, ErrBadRequest
		}
		addr = make([]byte, int(dal[0]))
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		addr = append(dal, addr...)
	default:
		return nil, ErrBadRequest
	}

	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	return &RequestTCP{
		Ver:     bb[0],
		Cmd:     bb[1],
		Rsv:     bb[2],
		Atyp:    bb[3],
		DstAddr: addr,
		DstPort: port,
	}, nil
}

// server
//
//	+----+-----+-------+------+----------+----------+
//	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
func NewReplyTCP(rep byte, atyp byte, bndaddr []byte, bndport []byte) *ReplyTCP {
	if atyp == ATYPDomain {
		bndaddr = append([]byte{byte(len(bndaddr))}, bndaddr...)
	}
	return &ReplyTCP{
		Ver:     Ver,
		Rep:     rep,
		Rsv:     0x00,
		Atyp:    atyp,
		BndAddr: bndaddr,
		BndPort: bndport,
	}
}

// client
//
//	+----+-----+-------+------+----------+----------+
//	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
func ReadReplyTCP(r io.Reader) (*ReplyTCP, error) {
	bb := make([]byte, 4)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}
	var addr []byte
	switch bb[3] {
	case ATYPIPv4:
		addr = make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	case ATYPIPv6:
		addr = make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	case ATYPDomain:
		dal := make([]byte, 1)
		if _, err := io.ReadFull(r, dal); err != nil {
			return nil, err
		}
		if dal[0] == 0 {
			return nil, ErrBadReply
		}
		addr = make([]byte, int(dal[0]))
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		addr = append(dal, addr...)
	default:
		return nil, ErrBadReply
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	return &ReplyTCP{
		Ver:     bb[0],
		Rep:     bb[1],
		Rsv:     bb[2],
		Atyp:    bb[3],
		BndAddr: addr,
		BndPort: port,
	}, nil
}

// client/server
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
func NewRequestUDP(atyp byte, dstaddr []byte, dstport []byte, data []byte) *DatagramUDP {
	if atyp == ATYPDomain {
		dstaddr = append([]byte{byte(len(dstaddr))}, dstaddr...)
	}
	return &DatagramUDP{
		Rsv:     []byte{0x00, 0x00},
		Frag:    0x00, // 00表示是一个独立片段
		Atyp:    atyp,
		DstAddr: dstaddr,
		DstPort: dstport,
		Data:    data,
	}
}

// server/server
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
func ReadRequestUDP(bb []byte) (*DatagramUDP, error) {
	n := len(bb)
	minl := 4
	if n < minl {
		return nil, ErrBadRequest
	}
	var addr []byte
	switch bb[3] {
	case ATYPIPv4:
		minl += 4
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-4 : minl]
	case ATYPIPv6:
		minl += 16
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-16 : minl]
	case ATYPDomain:
		minl += 1
		if n < minl {
			return nil, ErrBadRequest
		}
		l := bb[4]
		if l == 0 {
			return nil, ErrBadRequest
		}
		minl += int(l)
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-int(l) : minl]
		addr = append([]byte{l}, addr...)
	default:
		return nil, ErrBadRequest
	}

	minl += 2
	if n <= minl {
		return nil, ErrBadRequest
	}
	port := bb[minl-2 : minl]
	data := bb[minl:]
	d := &DatagramUDP{
		Rsv:     bb[0:2],
		Frag:    bb[2],
		Atyp:    bb[3],
		DstAddr: addr,
		DstPort: port,
		Data:    data,
	}
	return d, nil
}

func ParseAddress(address string) (a byte, addr []byte, port []byte, err error) {
	var h, p string
	h, p, err = net.SplitHostPort(address)
	if err != nil {
		return
	}
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		a = ATYPIPv4
		addr = []byte(ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		a = ATYPIPv6
		addr = []byte(ip6)
	} else {
		a = ATYPDomain
		addr = []byte(h)
	}
	i, _ := strconv.Atoi(p)
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(i))
	return
}

func ParseBytesAddress(b []byte) (a byte, addr []byte, port []byte, err error) {
	if len(b) < 1 {
		err = ErrEmptyAddr
		return
	}
	a = b[0]
	if a == ATYPIPv4 {
		if len(b) < 1+4+2 {
			err = ErrEmptyAddr
			return
		}
		addr = b[1 : 1+4]
		port = b[1+4 : 1+4+2]
		return
	}
	if a == ATYPIPv6 {
		if len(b) < 1+16+2 {
			err = ErrEmptyAddr
			return
		}
		addr = b[1 : 1+16]
		port = b[1+16 : 1+16+2]
		return
	}
	if a == ATYPDomain {
		if len(b) < 1+1 {
			err = ErrEmptyAddr
			return
		}
		l := int(b[1])
		if len(b) < 1+1+l+2 {
			err = ErrEmptyAddr
			return
		}
		addr = b[1 : 1+1+l]
		port = b[1+1+l : 1+1+l+2]
		return
	}
	err = ErrEmptyAddr
	return
}

func temporaryError(err error, wait time.Duration, maxDelay time.Duration) (time.Duration, bool) {
	if ne, ok := err.(net.Error); ok && ne.Temporary() {
		return delay(wait, maxDelay), true
	}
	return wait, false
}

func delay(wait, maxDelay time.Duration) time.Duration {
	if wait == 0 {
		wait = (maxDelay / 100)
	} else {
		wait *= 2
	}
	if wait >= maxDelay {
		wait = maxDelay
	}
	time.Sleep(wait)
	return wait
}

func copyData(dst io.Writer, src io.ReadCloser, bufferSize int) (written int64, err error) {
	buf := make([]byte, bufferSize)
	return io.CopyBuffer(dst, src, buf)
}
