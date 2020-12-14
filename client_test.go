package vsocks5
	
//import (
//	"testing"
//)
//
//func TestClient(t *testing.T){
//	client := &Client{
//		Server: "127.0.0.1:1081",
//		UserName:"",
//		Password:"",
//	}
//	conn, err := client.DialWithLocalAddr("udp", "", "127.0.0.1:803")
//	if err != nil {
//		t.Fatal(err)
//	}
//	conn.Write([]byte("test123"))
//	conn.Close()
//}