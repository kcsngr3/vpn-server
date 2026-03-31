package main

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"time"
)

// ip pool
type IPPool struct {
	usedIp map[byte]uint32
	mu     sync.Mutex
}

func newIPPool() *IPPool {
	return &IPPool{usedIp: make(map[byte]uint32)}
}
func (pool *IPPool) assignIP(sessionId uint32) (byte, uint32, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for i := byte(10); i <= 240; i++ {
		if _, used := pool.usedIp[i]; !used {
			pool.usedIp[i] = sessionId
			return i, sessionId, nil
		}
	}
	return 0, 0, fmt.Errorf("IP pool is full")
}
func (pool *IPPool) ReleaseIp(ipEnd byte) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	delete(pool.usedIp, ipEnd)
}
func (pool *IPPool) listIPPool() {
	for ip, session := range pool.usedIp {
		fmt.Printf("%d %x\n", ip, session)
	}

}

const preSharedKey string = "asd123"

// server
func ListenAuth(server *Server) {
	listenTcp, _ := net.Listen("tcp", ":9000")
	fmt.Println("Listen on:9000")
	go func() {
		for {
			conn, err := listenTcp.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				// make diffie
				curve := ecdh.X25519()
				serverPrivKey, err := curve.GenerateKey(rand.Reader)
				serverPubKey := serverPrivKey.PublicKey()

				mac := hmac.New(sha256.New, []byte(preSharedKey))
				mac.Write(serverPubKey.Bytes())

				//randem nonce and send
				conn.Write(serverPubKey.Bytes())
				conn.Write(mac.Sum(nil))

				//read i ncoming tcp
				clientPubKeyByte := make([]byte, 32)
				clientHmac := make([]byte, 32)

				io.ReadFull(conn, clientPubKeyByte)
				io.ReadFull(conn, clientHmac)

				//auth server
				macClient := hmac.New(sha256.New, []byte(preSharedKey))
				macClient.Write(clientPubKeyByte)
				if !hmac.Equal(clientHmac, macClient.Sum(nil)) {
					fmt.Println("Incorrect Client Hmac")
					return
				}

				// dh compute
				clientPubKey, _ := curve.NewPublicKey(clientPubKeyByte)
				sharedKey, _ := serverPrivKey.ECDH(clientPubKey)

				sessionEncKey := sha256.Sum256(sharedKey) // encap session key

				sessionId, vpnIpEnd, err := processAuth(server.ippool)
				if err != nil {
					fmt.Printf("Auth failed from %s: %v\n", c.RemoteAddr(), err) // log fail
					return
				}

				fmt.Printf("Auth OK from %s -> session=%x vpnIP=192.168.0.%d\n",
					c.RemoteAddr(), sessionId, vpnIpEnd) // log success
				addr := conn.RemoteAddr().(*net.TCPAddr)
				ip := addr.IP.To4()
				sessionIdStringHex := fmt.Sprintf("%x", sessionId) //make uint into strhex

				//need lock
				server.mu.Lock()
				server.session[sessionIdStringHex] = &ClientSession{nicIp: [4]byte{ip[0], ip[1], ip[2], ip[3]}, vpnIp: [4]byte{192, 168, 0, vpnIpEnd}, eh: *initEncryptHandler(sessionEncKey), sessionTime: time.Now()}
				server.dstIpToSessionId[vpnIpEnd] = sessionIdStringHex
				eh := server.session[sessionIdStringHex].eh
				server.mu.Unlock()

				// combine into one plaintext
				plaintext := make([]byte, 9)
				copy(plaintext[:8], []byte(sessionIdStringHex)) // 8 bytes session
				plaintext[8] = vpnIpEnd                         // 1 byte vpnIP

				// encrypt once
				encrypted := eh.encryptPlain(plaintext)
				c.Write(encrypted)

			}(conn)
		}
	}()
}

// server
func processAuth(ippool *IPPool) (uint32, byte, error) {
	vpnIpEnd, sessionId, err := ippool.assignIP(mrand.Uint32())
	if err == nil {
		return uint32(sessionId), byte(vpnIpEnd), nil
	} else {
		return 0, 0, fmt.Errorf("%s", err)
	}
}

// client
func SendAuth(client *Client, serverIp string) (int, error) {
	conn, err := net.Dial("tcp", serverIp+":9000")
	if err != nil {
		fmt.Println("Dial failed:", err)
		return 0, err
	}
	defer conn.Close()
	//

	// init keys for diffie
	curve := ecdh.X25519()
	clientPrivKey, err := curve.GenerateKey(rand.Reader)
	clientPubKey := clientPrivKey.PublicKey()
	mac := hmac.New(sha256.New, []byte(preSharedKey))
	mac.Write(clientPubKey.Bytes())

	//randem nonce and send
	conn.Write(clientPubKey.Bytes())
	conn.Write(mac.Sum(nil))

	//read i ncoming tcp
	serverPubKeyByte := make([]byte, 32)
	serverHmac := make([]byte, 32)

	io.ReadFull(conn, serverPubKeyByte)
	io.ReadFull(conn, serverHmac)

	//auth server
	macServer := hmac.New(sha256.New, []byte(preSharedKey))
	macServer.Write(serverPubKeyByte)
	if !hmac.Equal(serverHmac, macServer.Sum(nil)) {
		return 0, fmt.Errorf("INCORRECT Server HMAC")
	}

	// dh compute
	serverPubKey, _ := curve.NewPublicKey(serverPubKeyByte)
	sharedKey, _ := clientPrivKey.ECDH(serverPubKey)

	sessionEncKey := sha256.Sum256(sharedKey) // encap session key
	client.eh = *initEncryptHandler(sessionEncKey)

	ioBuf := make([]byte, 1500)
	n, _ := conn.Read(ioBuf)
	plaintext, err := client.eh.decrypt(ioBuf[:n])

	sessionId := string(plaintext[:8])
	fmt.Println(sessionId)
	client.sessionId = sessionId
	vpnIpEnd := plaintext[8]

	return int(vpnIpEnd), nil
}
