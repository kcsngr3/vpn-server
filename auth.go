package main

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// ip pool
type IPPool struct {
	usedIp map[byte]uint16
	mu     sync.Mutex
}

func newIPPool() *IPPool {
	return &IPPool{usedIp: make(map[byte]uint16)}
}
func (pool *IPPool) assignIP(sessionId uint16) (byte, uint16, error) {
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
	fmt.Println("Listen auth on:9000")
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
				// sessionIdStringHex := fmt.Sprintf("%04x", sessionId) //make uint into strhex

				//need lock
				server.mu.Lock()
				server.session[vpnIpEnd] = &ClientSession{nicIp: [4]byte{ip[0], ip[1], ip[2], ip[3]}, vpnIp: [4]byte{192, 168, 0, vpnIpEnd}, eh: *initEncryptHandler(sessionEncKey), sessionTime: time.Now(), clientToServer: initTrafficTracker(), serverToClient: initTrafficTracker()}
				// server.dstIpToSessionId[vpnIpEnd] = sessionIdStringHex
				eh := server.session[vpnIpEnd].eh
				server.mu.Unlock()

				// combine into one plaintext
				plaintext := make([]byte, 5)
				copy(plaintext[0:4], fmt.Sprintf("%04x", sessionId))
				plaintext[4] = vpnIpEnd // 1 byte vpnIP

				// encrypt once
				encrypted := eh.encryptPlain(plaintext)
				c.Write(encrypted)

			}(conn)
		}
	}()
}
func ListenHeartBeatClient(client *Client) {
	listenTcp, _ := net.Listen("tcp", ":9001")
	fmt.Println("Listen HB on:9001")
	go func() {
		for {
			conn, err := listenTcp.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))

				hbBuf := make([]byte, 2+8+32)
				if _, err := io.ReadFull(c, hbBuf); err != nil {
					return
				}

				// replay check
				ts := int64(binary.BigEndian.Uint64(hbBuf[2:10]))
				if time.Now().UnixNano()-ts > int64(10*time.Second) {
					fmt.Println("HB replay rejected")
					return
				}

				// verify server->client HMAC
				mac := hmac.New(sha256.New, client.eh.key[:])
				mac.Write([]byte("server->client"))
				mac.Write(hbBuf[:10])
				if !hmac.Equal(mac.Sum(nil), hbBuf[10:]) {
					fmt.Println("HB HMAC failed")
					return
				}

				// build response with fresh client timestamp
				clientRecv := time.Now().UnixNano()
				resp := make([]byte, 2+8+32)
				copy(resp[0:2], hbBuf[0:2])
				binary.BigEndian.PutUint64(resp[2:10], uint64(clientRecv))

				// re-sign with client->server label
				mac2 := hmac.New(sha256.New, client.eh.key[:])
				mac2.Write([]byte("client->server"))
				mac2.Write(resp[:10])
				copy(resp[10:], mac2.Sum(nil))

				c.Write(resp)
			}(conn)
		}
	}()
}
func ListenHeartBeatServer(server *Server) {
	listenTcp, _ := net.Listen("tcp", ":9001")
	fmt.Println("Listen HB on:9001")
	go func() {
		for {
			conn, err := listenTcp.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))

				resp := make([]byte, 2+8+32)
				if _, err := io.ReadFull(c, resp); err != nil {
					return
				}

				// lookup session by sessionId
				sessionId := binary.BigEndian.Uint16(resp[0:2])
				server.mu.RLock()
				var cs *ClientSession
				for _, s := range server.session {
					if binary.BigEndian.Uint16([]byte(s.sessionID[:2])) == sessionId {
						cs = s
						break
					}
				}
				server.mu.RUnlock()
				if cs == nil {
					return
				}

				// verify client->server HMAC
				mac := hmac.New(sha256.New, cs.eh.key[:])
				mac.Write([]byte("client->server"))
				mac.Write(resp[:10])
				if !hmac.Equal(mac.Sum(nil), resp[10:]) {
					fmt.Println("HB echo HMAC failed")
					return
				}

				clientTs := int64(binary.BigEndian.Uint64(resp[2:10]))
				clientToServer := time.Duration(time.Now().UnixNano() - clientTs)
				fmt.Printf("sessionId=%x c->s=%v\n", sessionId, clientToServer)

				cs.sessionTime = time.Now() // reset watchdog
			}(conn)
		}
	}()
}
func (s *Server) sendHeartbeats() {
	s.mu.RLock()
	sessions := make(map[byte]*ClientSession)
	for k, v := range s.session {
		sessions[k] = v
	}
	s.mu.RUnlock()

	for vpnIpEnd, cs := range sessions {
		go func(id byte, c *ClientSession) {
			if !s.sendHeartbeat(id, c) {
				fmt.Printf("HB failed vpnIp=%d closing session\n", id)
				s.ippool.ReleaseIp(c.vpnIp[3])
				s.mu.Lock()
				delete(s.session, id)
				s.mu.Unlock()
			}
		}(vpnIpEnd, cs)
	}
}
func (s *Server) sendHeartbeat(vpnIpEnd byte, cs *ClientSession) bool {
	addr := fmt.Sprintf("%d.%d.%d.%d:9001",
		cs.nicIp[0], cs.nicIp[1], cs.nicIp[2], cs.nicIp[3])

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	sentTs := time.Now().UnixNano()
	hb := make([]byte, 2+8+32)
	parsed, _ := strconv.ParseUint(cs.sessionID, 16, 16)
	binary.BigEndian.PutUint16(hb[0:2], uint16(parsed))
	binary.BigEndian.PutUint64(hb[2:10], uint64(sentTs))

	mac := hmac.New(sha256.New, cs.eh.key[:])
	mac.Write([]byte("server->client"))
	mac.Write(hb[:10])
	copy(hb[10:], mac.Sum(nil))

	if _, err := conn.Write(hb); err != nil {
		return false
	}

	resp := make([]byte, 2+8+32)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}

	// verify client->server HMAC
	mac2 := hmac.New(sha256.New, cs.eh.key[:])
	mac2.Write([]byte("client->server"))
	mac2.Write(resp[:10])
	if !hmac.Equal(mac2.Sum(nil), resp[10:]) {
		return false
	}

	rtt := time.Duration(time.Now().UnixNano() - sentTs)
	fmt.Printf("vpnIp=%d RTT=%.3fms\n", vpnIpEnd, float64(rtt)/float64(time.Millisecond))

	cs.sessionTime = time.Now()
	return true
}
func processAuth(ippool *IPPool) (uint16, byte, error) {
	for attempts := 0; attempts < 10; attempts++ {
		b := make([]byte, 2)
		rand.Read(b)
		sessionId := binary.BigEndian.Uint16(b)

		ippool.mu.Lock()
		// check sessionId not already in use
		alreadyUsed := false
		for _, existingSession := range ippool.usedIp {
			if existingSession == sessionId {
				alreadyUsed = true
				break
			}
		}
		ippool.mu.Unlock()

		if alreadyUsed {
			continue
		}

		vpnIpEnd, sessionId, err := ippool.assignIP(sessionId)
		if err != nil {
			return 0, 0, fmt.Errorf("%s", err)
		}
		return sessionId, vpnIpEnd, nil
	}
	return 0, 0, fmt.Errorf("could not allocate unique sessionId")
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

	sessionId := string(plaintext[0:4])
	fmt.Println(sessionId)
	client.sessionId = sessionId
	vpnIpEnd := plaintext[4]

	return int(vpnIpEnd), nil
}
