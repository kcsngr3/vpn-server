package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type ClientSession struct {
	nicIp             [4]byte
	vpnIp             [4]byte
	eh                encryptHandler
	sessionTime       time.Time
	sessionTrafficBit atomic.Uint64
	sessionID         string
	serverToClient    *trafficTracker
	clientToServer    *trafficTracker
}
type Server struct {
	fd     *os.File
	nicIP  [4]byte
	sendFd int
	recvFd int
	mu     sync.RWMutex
	ippool *IPPool // contain all interfaceID-byte , sessionID - uint16

	session map[byte]*ClientSession //map interfacce ip-byte , clientobj

	//dstIpToSessionId map[byte]byte //map i
}

func (s *Server) listAllSessionTraffic() {
	for _, cs := range s.session {
		// fmt.Printf("SessionID: %s , Traffic Bit: %d\n", cs.sessionID, cs.sessionTrafficBit.Load())
		fmt.Printf("SessionID: %s, SessionTime: %s, trfficByte: %d, scID: %d, csID: %d, scDropped: %d, csDropped: %d ", cs.sessionID, cs.sessionTime, cs.sessionTrafficBit.Load(), cs.serverToClient.highestId, cs.clientToServer.highestId, cs.serverToClient.droppedTraffic, cs.clientToServer.droppedTraffic)
	}

}

func initServer() (sendFd int, recvFd int) {
	sendFd, recvFd = initSockets("server")
	SetTUNip("vpntun", "192.168.0.1/24")
	return sendFd, recvFd
}

func (s *Server) filterTrafficFromClient(buf []byte, buffSize int) bool {
	if buffSize < 28 {
		return false
	}
	dstPort := uint16(buf[22])<<8 | uint16(buf[23])
	if dstPort != 51820 {
		return false
	}
	innerPacket := buf[28:buffSize]
	if len(innerPacket) < 20 {
		return false
	}
	return true
}

func (s *Server) filterTrafficToClient(buf []byte, buffSize int) bool {
	if buffSize < 20 {
		return false
	}
	if buf[16] != 192 || buf[17] != 168 || buf[18] != 0 {
		return false
	}
	if buf[19] == 1 {
		return false
	}
	return true
}

// decrypt  need a sessionId, and the unique eh taht contain each session privatekey and sessionkey for auth
func (s *Server) processDecapsulatedTraffic(buf []byte, buffSize int) {

	payload := buf[28:buffSize]
	vpnIpEnd := payload[0]
	idxPacket := payload[1:9]
	encrypted := payload[9:]

	s.mu.Lock()
	cs := s.session[vpnIpEnd]
	if cs == nil {
		s.mu.Unlock()
		return
	}
	cs.sessionTime = time.Now()
	s.mu.Unlock()

	cs.sessionTrafficBit.Add(uint64(buffSize))
	idx := binary.BigEndian.Uint64(idxPacket)
	if !cs.clientToServer.verifyId(idx) {
		cs.clientToServer.droppedTraffic++
		return
	}
	innerPacket, _ := cs.eh.decryptPacket(encrypted, idx, vpnIpEnd)

	// displayPacket("Server recive mess from client", buf, buffSize, 0)
	// displayPacket("Server send mess to internet", innerPacket, len(innerPacket), 0)
	if _, err := s.fd.Write(innerPacket); err != nil {
		fmt.Printf("TUN write error: %v\n", err)
	}
}

func (s *Server) sendEncapTrafficToClient(buf []byte, buffSize int) {
	vpnIpEnd := buf[19]
	s.mu.RLock()

	cs := s.session[vpnIpEnd]
	s.mu.RUnlock()

	if cs == nil {
		return
	}

	cs.sessionTrafficBit.Add(uint64(buffSize))
	idx := cs.serverToClient.incrementId()
	newp := encapsulateUdpPacket(s.nicIP, cs.nicIp, 51820, 51820, cs.eh.encryptPacket(buf[:buffSize], idx, cs.vpnIp[3]), idx, cs.vpnIp[3])
	// displayPacket("Server generated packet -> client", newp.data, int(newp.lengthOfData), 0)
	destAddr := &syscall.SockaddrInet4{Addr: cs.nicIp} // nicIp = real NIC IP to reach client
	if err := syscall.Sendto(s.sendFd, newp.data, 0, destAddr); err != nil {
		fmt.Printf("Sendto error: %v\n", err)
	}
}

// goIncomingTrafficFromClient receives encapsulated packets from client, decapsulates and writes to TUN
func (s *Server) goIncomingTrafficFromClient() {
	buf := make([]byte, 1500)
	for {
		buffSize, _, err := syscall.Recvfrom(s.recvFd, buf, 0)
		if err != nil {

			fmt.Printf("Recvfrom error: %v\n", err)
			continue
		}
		if !s.filterTrafficFromClient(buf, buffSize) {
			continue
		}
		//displayPacket("clint->server", buf, buffSize, 1)
		s.processDecapsulatedTraffic(buf, buffSize)
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
		if !s.filterTrafficToClient(buf, buffSize) {
			continue
		}
		// displayPacket("Server recive packets from internet", buf, buffSize, 0)
		s.sendEncapTrafficToClient(buf, buffSize)
	}
}

func (s *Server) Run() {
	go s.goIncomingTrafficFromClient()
	go s.goIncomingTrafficFromInternet()
}
func (s *Server) goWatchTimeOut() {
	ticker := time.NewTicker(20 * time.Second)
	for range ticker.C {
		s.sendHeartbeats() // HB handles sessionTime reset

		// collect timed out sessions
		var toDelete []byte
		s.mu.Lock()
		for id, cs := range s.session {
			if time.Since(cs.sessionTime) >= 60*time.Second {
				fmt.Printf("session %x timed out\n", id)
				toDelete = append(toDelete, id)
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
