package vsocks5

import (
	"bytes"
	"net"
	"testing"

	"github.com/456vv/x/tcptest"
	"github.com/issue9/assert/v2"
)

func Test_Client_Dial(t *testing.T) {
	as := assert.New(t, true)
	tcptest.D2S("0.0.0.0:0", func(conn net.Conn) {
		defer conn.Close()
		//\05\01\02
		nmr, err := ReadNegotiateMethodRequest(conn)
		as.NotError(err).Equal(nmr.Ver, 5).Equal(nmr.NMethods, 1).Equal(nmr.Methods, []byte{0x02})
		//\05\02
		NewNegotiateMethodReply(MethodUsernamePassword).WriteTo(conn)

		//\01\03123\03456
		nar, err := ReadNegotiateAuthRequest(conn)
		as.NotError(err).Equal(nar.Ver, 1)
		as.Equal(nar.Ulen, 3).Equal(nar.Uname, []byte("123"))
		as.Equal(nar.Plen, 3).Equal(nar.Passwd, []byte("456"))
		//\01\00
		NewNegotiateAuthReply(UserPassStatusSuccess).WriteTo(conn)

		// 05 01 00 01 7f 00 00 01 04 40
		//\05\01\00\01\7f\00\00\01\04@
		rtcp, err := ReadRequestTCP(conn)
		as.NotError(err).Equal(rtcp.Ver, 5)
		as.Equal(rtcp.Cmd, CmdConnect).Equal(rtcp.Rsv, 0).Equal(rtcp.Atyp, ATYPIPv4)
		as.Equal(rtcp.DstAddr, []byte{0x7f, 0x0, 0x0, 1}).Equal(rtcp.DstPort, []byte{0x4, 0x40})

		// 05 00 00 01 7f 00 00 01 04 d2
		//\05\00\00\01\7f\00\00\01\04\d2
		a, h, p, _ := ParseAddress("127.0.0.1:1234") // 这个是发起拨号的本地地址
		NewReplyTCP(RepSuccess, a, h, p).WriteTo(conn)

		b := make([]byte, 10)
		n, err := conn.Read(b)
		as.NotError(err)
		conn.Write(b[0:n])

		// t.Logf("% 0x", []byte{5, 0, 0, 1, 127, 0, 0, 1, 4, 210})
	}, func(raddr net.Addr) {
		c := &Client{
			Username: "123",
			Password: "456",
			Server:   raddr.String(),
			DialTCP: func(network string, laddr, raddr *net.TCPAddr) (net.Conn, error) {
				conn, err := net.DialTCP(network, laddr, raddr)
				if err != nil {
					return nil, err
				}
				n := &Negotiate{Conn: conn}
				if err = n.Auth("123", "456"); err != nil {
					return nil, err
				}
				return n, nil
			},
		}
		conn, err := c.Dial("tcp", "127.0.0.1:1088")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		p := []byte("123456")
		conn.Write(p)

		b := p
		n, err := conn.Read(b)
		as.NotError(err)
		if !bytes.Equal(p, b[0:n]) {
			t.Fatal("error")
		}
	})
}
