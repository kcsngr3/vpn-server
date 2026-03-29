package main

import (
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"syscall"
)

type Client struct {
	fd        *os.File
	nicIP     [4]byte
	srvIP     [4]byte
	sendFd    int
	recvFd    int
	counter   *atomic.Int64
	eh        encryptHandler
	sessionId byte // its shoudl be uint32-> now large number ->in hex
}

func initClient(authIp string) (sendFd int, recvFd int) {
	sendFd, recvFd = initSockets("client")
	SetTUNip("vpntun", authIp+"/24")
	return sendFd, recvFd
}

func (c *Client) filterClientTrafficToServer(buf []byte, buffSize int) bool {
	if buffSize < 20 {
		return false
	}
	if buf[16] == 239 || buf[16] == 224 {
		return false
	}
	if buf[12] == 0 {
		return false
	}
	return true
}

func (c *Client) filterClientTrafficToApp(buf []byte, buffSize int) bool {
	if buffSize < 20 {
		return false
	}
	return true
}

// encrypt
func (c *Client) sendEncapTrafficToServer(buf []byte, buffSize int) {
	newp := encapsulateUdpPacket(c.nicIP, c.srvIP, 51820, 51820, c.eh.encryptPacket(buf[:buffSize], c.sessionId), c.sessionId)
	fmt.Print(c.sessionId)
	dest := &syscall.SockaddrInet4{Port: 0, Addr: c.srvIP}
	// displayPacket("client->server", buf, buffSize, 1)
	if err := syscall.Sendto(c.sendFd, newp.data, 0, dest); err != nil {
		fmt.Printf("Sendto error: %v\n", err)
	}
}

func (c *Client) goReadVpnTun() {
	buf := make([]byte, 1500)
	for {
		buffSize, err := c.fd.Read(buf)
		if err != nil {
			log.Fatal(err)
		}
		if !c.filterClientTrafficToServer(buf, buffSize) {
			continue
		}
		c.sendEncapTrafficToServer(buf, buffSize)
	}
}

// decrypt
func (c *Client) goReadFromServer() {
	buf := make([]byte, 1500)
	for {
		buffSize, _, err := syscall.Recvfrom(c.recvFd, buf, 0)
		if err != nil {
			fmt.Printf("Recvfrom error: %v\n", err)
			continue
		}
		if !c.filterClientTrafficToApp(buf, buffSize) {
			continue
		}
		//displayPacket("server->client", buf, buffSize, 1)

		encryptedInner, _ := decapsulateUdpPacket(buf)
		plainP, _ := c.eh.decryptPacket(encryptedInner, c.sessionId)
		if _, err := c.fd.Write(plainP); err != nil {
			fmt.Printf("TUN write error: %v\n", err)
		}
	}
}

func (c *Client) Run() {
	go c.goReadVpnTun()
	go c.goReadFromServer()
}
