package main

import (
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
}
type Server struct {
	fd               *os.File
	nicIP            [4]byte
	sendFd           int
	recvFd           int
	mu               sync.RWMutex
	ippool           *IPPool
	session          map[string]*ClientSession
	dstIpToSessionId map[byte]string
}

func (s *Server) listAllSessionTraffic() {
	for sessionID, cs := range s.session {
		fmt.Printf("SessionID: %x , Traffic Bit: %d", sessionID, cs.sessionTrafficBit.Load())
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
	sessionId := string(payload[:4])
	encrypted := payload[4:]

	//only read not taht much of bottleneck
	s.mu.RLock()
	cs := s.session[sessionId] //ClientSession
	s.mu.RUnlock()
	if cs == nil {
		fmt.Printf("Unauthenticated traffic from client %x", sessionId)
		return
	}
	s.mu.Lock()
	cs.sessionTime = time.Now()
	s.mu.Unlock()

	cs.sessionTrafficBit.Add(uint64(buffSize))
	innerPacket, _ := cs.eh.decryptPacket(encrypted, sessionId)

	//displayPacket("server->internet", buf, buffSize, 0)
	if _, err := s.fd.Write(innerPacket); err != nil {
		fmt.Printf("TUN write error: %v\n", err)
	}
}

func (s *Server) sendEncapTrafficToClient(buf []byte, buffSize int) {
	vpnIpEnd := buf[19]
	s.mu.RLock()
	sessionId := s.dstIpToSessionId[vpnIpEnd]
	cs := s.session[sessionId]
	s.mu.RUnlock()

	if sessionId == "" || cs == nil {
		return
	}

	cs.sessionTrafficBit.Add(uint64(buffSize))
	newp := encapsulateUdpPacket(s.nicIP, cs.nicIp, 51820, 51820, cs.eh.encryptPacket(buf[:buffSize], sessionId), sessionId)
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
		//displayPacket("internet->server", buf, buffSize, 0)
		s.sendEncapTrafficToClient(buf, buffSize)
	}
}

func (s *Server) Run() {
	go s.goIncomingTrafficFromClient()
	go s.goIncomingTrafficFromInternet()
}
func (s *Server) goWatchTimeOut() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		s.mu.Lock()
		for sessionId, cs := range s.session {
			if time.Since(cs.sessionTime) >= 60*time.Second {
				fmt.Printf("session %x timed out, disconnecting\n", sessionId)
				// cleanup
				s.ippool.ReleaseIp(cs.vpnIp[3])
				delete(s.dstIpToSessionId, cs.vpnIp[3])
				delete(s.session, sessionId)
			}
		}
		s.mu.Unlock()
	}
}
