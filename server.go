package main

import (
	"fmt"
	"os"
	"sync"
	"syscall"
)

type ClientSession struct {
	nicIp [4]byte
	vpnIp [4]byte
	eh    encryptHandler
}
type Server struct {
	fd               *os.File
	nicIP            [4]byte
	sendFd           int
	recvFd           int
	mu               sync.RWMutex
	ippool           *IPPool
	session          map[byte]*ClientSession
	dstIpToSessionId map[byte]byte
}

func initServer() (sendFd int, recvFd int) {
	sendFd, recvFd = initSockets("server")
	SetTUNip("vpntun", "192.168.0.1/24")
	return sendFd, recvFd
}

func (s *Server) filterTrafficFromClient(buf []byte, buffSize int) bool {
	if buffSize < 49 { // 28 + 1 session + 20 min encrypted
		return false
	}
	// ignore own packets
	if buf[12] == s.nicIP[0] && buf[13] == s.nicIP[1] &&
		buf[14] == s.nicIP[2] && buf[15] == s.nicIP[3] {
		return false
	}
	dstPort := uint16(buf[22])<<8 | uint16(buf[23])
	if dstPort != 51820 {
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

	encryptInner, sessionId := decapsulateUdpPacket(buf)
	//only read not taht much of bottleneck
	s.mu.RLock()
	cs := s.session[sessionId] //ClientSession
	fmt.Println(sessionId)
	s.mu.RUnlock()

	innerPacket, err := cs.eh.decryptPacket(encryptInner, sessionId)
	if err != nil {
		fmt.Printf("decrypt failed: %v sessionId=%02x\n", err, sessionId)
		return // ADD THIS
	}

	//displayPacket("server->internet", buf, buffSize, 0)
	if _, err := s.fd.Write(innerPacket); err != nil {
		fmt.Printf("TUN write error: %v\n", err)
	}
}

// encrypt dst ip-> some vpntun fetch the src
func (s *Server) sendEncapTrafficToClient(buf []byte, buffSize int) {
	vpnIpEnd := buf[19]
	s.mu.RLock()
	sessionId := s.dstIpToSessionId[vpnIpEnd]
	clientIP := s.session[sessionId].nicIp
	eh := s.session[sessionId].eh
	s.mu.RUnlock()

	if clientIP == ([4]byte{}) {
		return
	}
	// one is for fingerprint and one is for header but, since client will always know his own session no need for o send
	newp := encapsulateUdpPacket(s.nicIP, clientIP, 51820, 51820, eh.encryptPacket(buf[:buffSize], sessionId), sessionId)
	//displayPacket("encap->client", buf, buffSize, 0)
	destAddr := &syscall.SockaddrInet4{Addr: clientIP}
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
