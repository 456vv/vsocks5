package vsocks5

import (
	"errors"
)

var (
	ErrVersion         = errors.New("invalid Version")
	ErrUserPassVersion = errors.New("invalid Version of Username Password Auth")
	ErrBadRequest      = errors.New("bad Request")
	ErrEmptyAddr       = errors.New("invalid Addr")
	ErrHandler         = errors.New("data handler is not set")
	ErrUnsupportCmd    = errors.New("unsupport Command")
	ErrUserPassAuth    = errors.New("invalid Username or Password for Auth")
	ErrTCPConnClose    = errors.New("TCP connection is closed")
	ErrBadReply        = errors.New("bad Reply")
)

var BuffSize = 32 << 10 // 32k

type Cmd []byte

const (
	// CmdConnect 是 TCP 命令
	CmdConnect byte = 0x01
	// CmdBind 是绑定端口命令
	CmdBind byte = 0x02
	// CmdUDP 是 UDP 命令
	CmdUDP byte = 0x03
)

const (
	// MethodNone 是默认方法
	MethodNone byte = 0x00
	// MethodGSSAPI 是gssapi方法
	MethodGSSAPI byte = 0x01 // MUST support // todo
	// MethodUsernamePassword 是用户名/密码授权方法
	MethodUsernamePassword byte = 0x02 // SHOULD support
	// MethodUnsupportAll 表示不支持所有给定的方法
	MethodUnsupportAll byte = 0xFF
)

const (
	// ver是socks协议版本
	Ver byte = 0x05

	// UserPassVer 是用户名/密码授权协议版本
	UserPassVer byte = 0x01
	// UserPassStatusSuccess 是用户名/密码授权的成功状态
	UserPassStatusSuccess byte = 0x00
	// UserPassStatusFailure 是用户名/密码授权的失败状态
	UserPassStatusFailure byte = 0x01 // just other than 0x00

	// ATYPIPv4 是ipv4地址类型
	ATYPIPv4 byte = 0x01 // 4 octets
	// ATYPDomain 是域名地址类型
	ATYPDomain byte = 0x03 // The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.
	// ATYPIPv6 is ipv6 地址类型
	ATYPIPv6 byte = 0x04 // 16 octets

	// RepSuccess 意味着回复成功
	RepSuccess byte = 0x00
	// RepServerFailure 意味着服务器故障
	RepServerFailure byte = 0x01
	// RepNotAllowed 表示请求不允许
	RepNotAllowed byte = 0x02
	// RepNetworkUnreachable 表示网络不可达
	RepNetworkUnreachable byte = 0x03
	// RepHostUnreachable 表示主机无法访问
	RepHostUnreachable byte = 0x04
	// RepConnectionRefused 表示连接被拒绝
	RepConnectionRefused byte = 0x05
	// RepTTLExpired 表示 TTL 已过期
	RepTTLExpired byte = 0x06
	// RepCommandNotSupported 表示不支持请求命令
	RepCommandNotSupported byte = 0x07
	// RepAddressNotSupported 表示不支持请求地址
	RepAddressNotSupported byte = 0x08
)
