package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type ClientSession struct {
	udpAddrDest         atomic.Pointer[net.UDPAddr] //
	authIp              string
	vpnIp               [4]byte
	eh                  encryptHandler
	sessionTime         time.Time
	sessionIdleTime     time.Time
	sessionLatency      time.Duration
	sessionTrafficBytes atomic.Uint64
	sessionID           string
	serverToClient      *trafficTracker
	clientToServer      *trafficTracker
	dbSessionID         string
}
type Server struct {
	fd      *os.File
	conn    net.PacketConn
	mu      sync.RWMutex
	ippool  *IPPool // contain all interfaceID-byte , sessionID - uint16
	db      *DbHandler
	session map[byte]*ClientSession //map interfacce ip-byte , clientobj

}

func (s *Server) listAllSessionTraffic() {
	for _, cs := range s.session {
		// fmt.Printf("SessionID: %s , Traffic Bit: %d\n", cs.sessionID, cs.sessionTrafficBit.Load())
		fmt.Printf("SessionID: %s, SessionTime: %s, trfficByte: %d, scID: %d, csID: %d, scDropped: %d, csDropped: %d ", cs.sessionID, cs.sessionTime, cs.sessionTrafficBytes.Load(), cs.serverToClient.highestId, cs.clientToServer.highestId, cs.serverToClient.droppedTraffic.Load(), cs.clientToServer.droppedTraffic.Load())
	}

}

func initServer(ipStringMask string) net.PacketConn {
	SetTUNip("vpntun", ipStringMask)
	conn, err := net.ListenPacket("udp", ":51820")
	if err != nil {
		log.Fatal(err)
	}
	return conn
}

// decrypt  need a sessionId, and the unique eh taht contain each session privatekey and sessionkey for auth
func (s *Server) processDecapsulatedTraffic(buf []byte, buffSize int, clientIpAddr net.Addr) {

	idxPacket, vpnIpEnd, encrypted := decapsulatesPacket(buf, buffSize)
	// payload := buf[28:buffSize]
	// vpnIpEnd := payload[0]
	// idxPacket := payload[1:9]
	// encrypted := payload[9:]

	s.mu.Lock()
	cs := s.session[vpnIpEnd]
	if cs == nil {
		s.mu.Unlock()
		return
	}
	cs.sessionTime = time.Now()
	s.mu.Unlock()
	cs.udpAddrDest.Store(clientIpAddr.(*net.UDPAddr))
	cs.sessionTrafficBytes.Add(uint64(buffSize))

	if !cs.clientToServer.verifyId(idxPacket) {
		cs.clientToServer.droppedTraffic.Add(1)
		return
	}
	innerPacket, decryptError := cs.eh.decryptPacket(encrypted, idxPacket, vpnIpEnd)
	if decryptError != nil {
		fmt.Printf("Decrypt error: ", decryptError)
		cs.clientToServer.droppedTraffic.Add(1)
		return
	}
	// displayPacket("Server recive mess from client", buf, buffSize, 0)
	// displayPacket("Server send mess to internet", innerPacket, len(innerPacket), 0)
	if _, err := s.fd.Write(innerPacket); err != nil {
		fmt.Printf("TUN write error: %v\n", err)
	}
}

func (s *Server) sendEncapTrafficToClient(buf []byte, buffSize int) {
	vpnIpEnd := buf[19] // dest ip, should be

	s.mu.RLock()
	cs := s.session[vpnIpEnd]
	s.mu.RUnlock()

	if cs == nil {
		return
	}
	addr := cs.udpAddrDest.Load()
	if addr == nil {
		return
	}
	idx := cs.serverToClient.incrementId()
	encrypted := cs.eh.encryptPacket(buf[:buffSize], idx, vpnIpEnd)
	_, err := s.conn.WriteTo(encapsulatePacket(idx, vpnIpEnd, encrypted), addr)
	if err != nil {
		cs.serverToClient.droppedTraffic.Add(1)
		return
	}
	cs.sessionTrafficBytes.Add(uint64(buffSize))

}

// goIncomingTrafficFromClient receives encapsulated packets from client, decapsulates and writes to TUN
func (s *Server) goIncomingTrafficFromClient() {
	buf := make([]byte, 1500)
	for {
		buffSize, clientIpAddr, _ := s.conn.ReadFrom(buf)

		s.processDecapsulatedTraffic(buf, buffSize, clientIpAddr)
	}
}

// goIncomingTrafficFromInternet reads replies from TUN, re-encapsulates and sends back to client
func (s *Server) goIncomingTrafficFromInternet() {
	buf := make([]byte, 1500)
	for {
		buffSize, err := s.fd.Read(buf)
		if err != nil {
			fmt.Printf("TUN read error: %v\n", err)
			continue
		}
		if buffSize < 9 {
			continue
		}
		s.sendEncapTrafficToClient(buf, buffSize)
	}
}

func (s *Server) Run() {
	go s.goIncomingTrafficFromClient()
	go s.goIncomingTrafficFromInternet()
	go s.goLogToRegionDb()
	go s.goWatchTimeOut()
}
func (s *Server) goWatchTimeOut() {
	ticker := time.NewTicker(20 * time.Second)
	for range ticker.C {

		// collect timed out sessions
		var toDelete []byte
		s.mu.Lock()
		for id, cs := range s.session {
			if time.Since(cs.sessionTime) >= 60*time.Second || time.Since(cs.sessionIdleTime) >= 2*time.Minute {
				fmt.Printf("session - %s timed out\n", cs.sessionID)
				toDelete = append(toDelete, id)
				err := s.db.TxDisconnectByHbFail(cs.dbSessionID, 0)
				if err != nil {
					fmt.Printf("Failed to close session %s: %v\n", cs.sessionID, err)
				}
			}
		}
		s.mu.Unlock()

		// delete outside iteration
		for _, id := range toDelete {
			s.ippool.ReleaseIp(s.session[id].vpnIp[3])
			s.mu.Lock()
			delete(s.session, id)

			s.mu.Unlock()
		}
	}
}
func (s *Server) goLogToRegionDb() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		s.mu.RLock()
		for _, cs := range s.session {
			addr := cs.udpAddrDest.Load()
			if addr == nil {
				continue
			}
			go s.db.TxInsertSessionSnapshot(
				cs.dbSessionID,
				addr.String(),
				int64(cs.serverToClient.highestId),
				int64(cs.clientToServer.highestId),
				int64(cs.clientToServer.droppedTraffic.Load()),
				int64(cs.sessionTrafficBytes.Load()),
				cs.sessionLatency.Seconds(),
			)
		}
		s.mu.RUnlock()
	}
}
func (s *Server) closeAllSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, cs := range s.session {
		err := s.db.TxDisconnectByHbFail(cs.dbSessionID, 0)
		if err != nil {
			fmt.Printf("Failed to close session %s: %v\n", cs.sessionID, err)
		}
		s.ippool.ReleaseIp(cs.vpnIp[3])
	}
	s.session = make(map[byte]*ClientSession)
}
