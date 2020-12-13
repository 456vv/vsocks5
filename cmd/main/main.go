package main

import (
	"github.com/456vv/vsocks5"
	"github.com/456vv/vconnpool/v2"
	"github.com/456vv/vconn"
    "golang.org/x/crypto/ssh"
    "net"
    "net/url"
    "time"
    "flag"
    "fmt"
    "log"
    "io"
    "os"
    "bytes"
    "errors"
    "encoding/base64"
)

var (
    flog = flag.String("log", "", "日志文件(默认留空在控制台显示日志)  (format \"./vsocks5.txt\")")
    fuser = flag.String("user", "", "用户名")
    fpwd = flag.String("pwd", "", "密码")
    faddr = flag.String("addr", "", "代理服务器地 (format \"0.0.0.0:1080\")")
    fproxy = flag.String("proxy", "", "代理服务器的上级代理IP地址 (format \"https://admin:admin@11.22.33.44:8888\" or \"ssh://admin:admin@11.22.33.44:22\")")
    fdataBufioSize = flag.Int("dataBufioSize", 1024*10, "代理数据交换缓冲区大小，单位字节")
)

func main(){
    flag.Parse()
    if flag.NFlag() == 0 {
        flag.PrintDefaults()
        fmt.Println("\r\n命令行例子：vsocks5 -addr 0.0.0.0:1080")
        return
    }
    var out io.Writer = os.Stdout
    if *flog != "" {
        file, err := os.OpenFile(*flog, os.O_CREATE | os.O_RDWR, 0777)
        if err != nil {
            fmt.Println("日志文件错误：", err)
            return
        }
        out = file
    }
	
	handle := &vsocks5.DefaultHandle{
		BuffSize: *fdataBufioSize,
	}
	s5 := vsocks5.Server{
		Supported: []byte{vsocks5.CmdConnect, vsocks5.CmdUDP},
		Addr: *faddr,
		Handle: handle,
		ErrorLog: log.New(out, "", log.Lshortfile|log.LstdFlags),
	}
	if *fuser != "" {
		s5.Method = vsocks5.MethodUsernamePassword
		s5.Auth = func(username, password string) bool {
			fmt.Println(username, password, *fuser, *fpwd)
		    return username == *fuser && password == *fpwd
		}
	}
	if *fproxy != "" {
		u, err := url.Parse(*fproxy)
		if err != nil {
            fmt.Println("代理地址格式错误：", err)
            return
		}
		puser := u.User.Username()
		ppwd, _ := u.User.Password()
		if u.Scheme == "ssh" {
			//ssh代理
			config := &ssh.ClientConfig{
				User: puser,
				Auth: []ssh.AuthMethod{
					ssh.Password(ppwd),
				},
				HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					log.Println(hostname, remote, key)
					return nil
		        },
		        HostKeyAlgorithms: []string{
					ssh.KeyAlgoRSA,
					ssh.KeyAlgoDSA,
					ssh.KeyAlgoECDSA256,
					ssh.KeyAlgoECDSA384,
					ssh.KeyAlgoECDSA521,
					ssh.KeyAlgoED25519,
				},
				Timeout: 5 * time.Second,
			}
			
			sshConn, client, err := sshDial("tcp", u.Host, config)
			if err != nil {
				fmt.Println("代理拨号错误: ", err)
	            return
			}
			
			defer func(){
				client.Close()
			}()
			handle.Dialer.Dial=func(network, address string) (net.Conn, error){
				select {
				case <-sshConn.(vconn.CloseNotifier).CloseNotify():
					sshConn, client, err = sshDial("tcp", u.Host, config)
					if err != nil {
						return nil, err
					}
				default:
				}
				return client.Dial(network, address)
			}
		}else if u.Scheme == "http" || u.Scheme == "https" {
			connPool := &vconnpool.ConnPool{
				Dialer: &net.Dialer{
					Timeout: 5 * time.Second,
					DualStack: true,
				},
				IdeTimeout: time.Minute,
			}
			
			handle.Dialer.Dial=func(network, address string) (net.Conn, error){
				pconn, err := connPool.Dial(network, u.Host)
				if err != nil {
					return nil, err
				}
				if u.Scheme == "http" {
					return pconn, err
				}
				
				var pauth string
				if puser != "" {
					pauth = "\nProxy-Authorization: Basic " +basicAuth(puser, puser)
				}
				pconn.Write([]byte(fmt.Sprintf("CONNECT %[1]s HTTP/1.1\r\nHost: %[1]s%s\r\n\r\n", address, pauth)))
				
				resultStatus200 := []byte("HTTP/1.1 200 Connection established\r\n\r\n")
				p := make([]byte, 39)
				n, err := pconn.Read(p)
				if err != nil {
					return nil, err
				}
				if bytes.Compare(resultStatus200, p[:n]) != 0 {
					pconn.Close()
					return nil, errors.New("https proxy not support")
				}
				return pconn, err
			}
		}
	}	
   	defer s5.Close()
    err := s5.ListenAndServe()
    if err != nil {
		log.Printf("vsocks5-Error：%s", err)
    }
}

func sshDial(network, addr string, config *ssh.ClientConfig) (net.Conn, *ssh.Client, error){
	conn, err := net.DialTimeout(network, addr, config.Timeout)
	if err != nil {
		return nil, nil, err
	}
	
	conn = vconn.NewConn(conn)
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, nil, err
	}
	
	return conn, ssh.NewClient(c, chans, reqs), nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}