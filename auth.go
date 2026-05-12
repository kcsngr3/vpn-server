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
				//read i ncoming tcp
				clientPubKeyByte := make([]byte, 32)
				clientHmac := make([]byte, 32)

				io.ReadFull(conn, clientPubKeyByte)
				io.ReadFull(conn, clientHmac)

				// make diffie
				curve := ecdh.X25519()
				serverPrivKey, err := curve.GenerateKey(rand.Reader)
				serverPubKey := serverPrivKey.PublicKey()

				mac := hmac.New(sha256.New, []byte(preSharedKey))
				mac.Write(serverPubKey.Bytes())

				//randem nonce and send
				conn.Write(serverPubKey.Bytes())
				conn.Write(mac.Sum(nil))

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

				server.session[vpnIpEnd] = &ClientSession{authIp: ip.String(), sessionID: fmt.Sprintf("%04x", sessionId), vpnIp: [4]byte{192, 168, 0, vpnIpEnd}, eh: *initEncryptHandler(sessionEncKey), sessionTime: time.Now(), sessionIdleTime: time.Now(), clientToServer: initTrafficTracker(), serverToClient: initTrafficTracker()}
				// server.dstIpToSessionId[vpnIpEnd] = sessionIdStringHex
				cs := server.session[vpnIpEnd]
				//db
				dbSessinID, errDb := server.db.TxCreateSession(fmt.Sprintf("%04x", sessionId), "192.168.0."+fmt.Sprintf("%d", vpnIpEnd), fmt.Sprintf("%x", cs.eh.key))
				cs.dbSessionID = dbSessinID
				server.mu.Unlock()

				// combine into one plaintext
				plaintext := make([]byte, 5)
				copy(plaintext[0:4], fmt.Sprintf("%04x", sessionId))
				plaintext[4] = vpnIpEnd // 1 byte vpnIP

				// encrypt once
				encrypted := cs.eh.encryptPlain(plaintext)
				c.Write(encrypted)

				if errDb != nil {
					fmt.Printf("Db creating session Error: ")
				}
			}(conn)
		}
	}()
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

// hb
func (client *Client) sendHearthBeat() bool {
	// strip the port first
	serverAddr := client.conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(serverAddr)
	conn, err := net.DialTimeout("tcp", host+":9001", 3*time.Second)

	if err != nil {
		fmt.Println(err)
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second)) // if eaither sides dies durring hb
	clientHbTs := time.Now().UnixNano()
	hbMess := make([]byte, 4+8+32)

	// write sessionId
	copy(hbMess[0:4], []byte(client.sessionId))

	// timestamp
	binary.BigEndian.PutUint64(hbMess[4:12], uint64(clientHbTs))

	// sign
	mac := hmac.New(sha256.New, client.eh.key[:])
	mac.Write([]byte(client.sessionId + "0")) // 0 represent client
	mac.Write(hbMess[:12])
	copy(hbMess[12:], mac.Sum(nil))
	conn.Write(hbMess)

	resp := make([]byte, 4+8+32)
	io.ReadFull(conn, resp)
	//verify
	mac2 := hmac.New(sha256.New, client.eh.key[:])
	mac2.Write([]byte(client.sessionId + "1")) // 1 represent server
	mac2.Write(resp[:12])
	if !hmac.Equal(mac2.Sum(nil), resp[12:]) {
		fmt.Println("hmac fails2")
		return false

	}

	rtt := time.Duration(time.Now().UnixNano() - clientHbTs)
	fmt.Printf("RTT=%.3fms\n", float64(rtt)/float64(time.Millisecond))

	hbLatency := make([]byte, 4+8+32)
	copy(hbLatency[0:4], []byte(client.sessionId))           // sessionId 4 bytes
	binary.BigEndian.PutUint64(hbLatency[4:12], uint64(rtt)) // rtt 8 bytes

	mac3 := hmac.New(sha256.New, client.eh.key[:])
	mac3.Write([]byte(client.sessionId + "2"))
	mac3.Write(hbLatency[:12]) // sessionId + rtt
	copy(hbLatency[12:], mac3.Sum(nil))

	conn.Write(hbLatency)
	return true

}
func (server *Server) ListenHeartBeatServer() {
	listenTcp, _ := net.Listen("tcp", ":9001")
	fmt.Println("Listen hb on:9001")
	go func() {
		for {
			conn, _ := listenTcp.Accept()
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))

				hbMess := make([]byte, 4+8+32)
				io.ReadFull(c, hbMess)

				// lookup session
				sessionId := string(hbMess[:4])
				server.mu.RLock()
				var cs *ClientSession
				for _, s := range server.session {
					if s.sessionID == sessionId {
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
				mac.Write([]byte(sessionId + "0"))
				mac.Write(hbMess[:12])
				if !hmac.Equal(mac.Sum(nil), hbMess[12:]) {
					return
				}

				// reset watchdog
				cs.sessionIdleTime = time.Now()

				// echo back signed with server->client
				resp := make([]byte, 4+8+32)
				copy(resp[0:12], hbMess[0:12]) // same sessionId + timestamp
				mac2 := hmac.New(sha256.New, cs.eh.key[:])
				mac2.Write([]byte(sessionId + "1"))
				mac2.Write(resp[:12])
				copy(resp[12:], mac2.Sum(nil))
				c.Write(resp)

				ttrMess := make([]byte, 4+8+32)
				io.ReadFull(c, ttrMess)
				sessionIdTtr := string(ttrMess[0:4])

				if sessionIdTtr != sessionId {
					return
				}

				mac3 := hmac.New(sha256.New, cs.eh.key[:])
				mac3.Write([]byte(sessionId + "2"))
				mac3.Write(ttrMess[:12])
				if !hmac.Equal(mac3.Sum(nil), ttrMess[12:]) {
					return
				}

				server.mu.Lock()
				cs.sessionLatency = time.Duration(binary.BigEndian.Uint64(ttrMess[4:12]))
				latencyLocal := time.Duration(binary.BigEndian.Uint64(ttrMess[4:12]))
				server.db.InsertHb(cs.dbSessionID, cs.sessionLatency.Seconds(), true)
				server.mu.Unlock()
				fmt.Printf("Session: %s Latency: %v \n", sessionId, latencyLocal)

			}(conn)
		}
	}()
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
