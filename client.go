package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

type Client struct {
	fd             *os.File
	conn           net.Conn
	eh             encryptHandler
	sessionId      string // its shoudl be uint32-> now large number ->in hex
	vpnIpEnd       byte
	clientToServer *trafficTracker
	serverToClient *trafficTracker
}

func initClient(authIp string, serverIP string) net.Conn {
	SetTUNip("vpntun", authIp+"/24")
	conn, err := net.Dial("udp", serverIP+":51820")
	if err != nil {
		log.Fatal(err)
	}
	return conn
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
	idx := c.clientToServer.incrementId()
	encrypt := c.eh.encryptPacket(buf[:buffSize], idx, c.vpnIpEnd)
	_, err := c.conn.Write(encapsulatePacket(idx, c.vpnIpEnd, encrypt))

	if err != nil {
		fmt.Printf("Error with sending encap to server %v\n", err)
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
		n, err := c.conn.Read(buf)
		if err != nil {
			fmt.Printf("Server read error: %v\n", err)
			return //
		}
		if n < 9 { // 1 byte vpnIpEnd + 8 bytes idx minimum
			continue
		}
		idxS, vpnIP, encrypted := decapsulatesPacket(buf, n)

		if vpnIP == c.vpnIpEnd && c.serverToClient.verifyId(idxS) {
			plainP, _ := c.eh.decryptPacket(encrypted, idxS, vpnIP)
			if _, err := c.fd.Write(plainP); err != nil {
				fmt.Printf("TUN write error: %v\n", err)
			}
		}

	}
}
func (c *Client) goSendHearthBeat() {
	ticker := time.NewTicker(20 * time.Second)
	for range ticker.C {
		c.sendHearthBeat()
	}
}
func (c *Client) Run() {
	go c.goReadVpnTun()
	go c.goReadFromServer()
	go c.goSendHearthBeat()
}
