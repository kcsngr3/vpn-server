package main

import (
	"fmt"
	"log"
	"sync/atomic"
	"syscall"
)

// Global sockets
var sendFd int // IPPROTO_RAW  → sendto() to NIC
var rawFd int  // IPPROTO_TCP  → recvfrom() from NIC

type Packet struct {
	protocol    byte
	src         [4]byte
	dst         [4]byte
	payload     []byte
	packageSize int
	counter     int
}

func (p *Packet) displayPacket(note string) {
	if p.dst[0] != byte(239) &&
		p.dst[0] != byte(240) &&
		p.dst[0] != byte(224) {

		fmt.Println(note)
		fmt.Printf("Time %d\n", p.counter)
		fmt.Printf("Got packet: %d bytes\n", p.packageSize)
		fmt.Printf("Protocol: %d\n", p.protocol)
		fmt.Printf("Src IP: %d.%d.%d.%d\n", p.src[0], p.src[1], p.src[2], p.src[3])
		fmt.Printf("Dst IP: %d.%d.%d.%d\n", p.dst[0], p.dst[1], p.dst[2], p.dst[3])
		fmt.Printf("Payload: %x\n", p.payload)
	}
}

func calculateHeaderChecksum(header []byte) uint16 {
	sum := uint32(0)

	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}

	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

func initSockets() {
	var err error

	// --- sendFd: IPPROTO_RAW, send only, bound to enp3s0 ---
	sendFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal("sendFd Socket failed:", err)
	}
	err = syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatal("sendFd IP_HDRINCL failed:", err)
	}
	err = syscall.SetsockoptString(sendFd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "enp3s0")
	if err != nil {
		log.Fatal("sendFd SO_BINDTODEVICE failed:", err)
	}

	// --- rawFd: IPPROTO_TCP, recv only, bound to NIC IP ---
	rawFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatal("rawFd Socket failed:", err)
	}
	err = syscall.Bind(rawFd, &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{10, 0, 0, 101}, // your NIC IP
	})
	if err != nil {
		log.Fatal("rawFd Bind failed:", err)
	}
}

func main() {
	counter := atomic.Int64{}

	initSockets()

	fd, name, err := OpenTUN("vpntun")
	if err != nil {
		log.Fatal("OpenTUN failed:", err)
	}
	SetTUNip("vpntun", "192.168.0.10/24")
	fmt.Println("Interface:", name)

	// TUN → Real NIC (outgoing traffic)
	go func() {
		for {
			buf := make([]byte, 1500)
			n, err := fd.Read(buf)
			if err != nil {
				log.Fatal("TUN read error:", err)
			}

			if n < 20 {
				continue
			}

			// Skip multicast/broadcast
			if buf[16] == 239 || buf[16] == 224 {
				continue
			}

			if buf[12] == 0 {
				continue
			}

			// Create packet struct for display
			p := Packet{
				counter:     int(counter.Add(1)),
				packageSize: n,
				protocol:    buf[9],
				src:         [4]byte{buf[12], buf[13], buf[14], buf[15]},
				dst:         [4]byte{buf[16], buf[17], buf[18], buf[19]},
				payload:     buf[20:n],
			}
			p.displayPacket("app->vpn")

			// Rewrite source IP to real NIC IP
			buf[12] = 10
			buf[13] = 0
			buf[14] = 0
			buf[15] = 101

			// Recalculate checksum
			buf[10] = 0
			buf[11] = 0
			checksum := calculateHeaderChecksum(buf[:20])
			buf[10] = byte(checksum >> 8)
			buf[11] = byte(checksum & 0xff)

			// Send out via raw socket to NIC
			destAddr := &syscall.SockaddrInet4{
				Port: 0,
				Addr: [4]byte{buf[16], buf[17], buf[18], buf[19]},
			}
			err = syscall.Sendto(sendFd, buf[:n], 0, destAddr)
			if err != nil {
				fmt.Printf("Sendto error: %v\n", err)
			}
		}
	}()

	// Real NIC → TUN (incoming traffic)
	go func() {
		for {
			buf := make([]byte, 1500)

			n, _, err := syscall.Recvfrom(rawFd, buf, 0)
			if err != nil {
				fmt.Printf("Recvfrom error: %v\n", err)
				continue
			}

			if n < 20 {
				continue
			}

			// Skip multicast/broadcast
			if buf[16] == 239 || buf[16] == 224 {
				continue
			}

			// Only accept packets destined to our NIC IP
			if buf[16] != 10 || buf[17] != 0 || buf[18] != 0 || buf[19] != 101 {
				continue
			}

			//Create packet struct for display
			p := Packet{
				counter:     int(counter.Add(1)),
				packageSize: n,
				protocol:    buf[9],
				src:         [4]byte{buf[12], buf[13], buf[14], buf[15]},
				dst:         [4]byte{buf[16], buf[17], buf[18], buf[19]},
				payload:     buf[20:n],
			}
			p.displayPacket("vpn->app")

			// Rewrite destination IP back to TUN IP
			buf[16] = 192
			buf[17] = 168
			buf[18] = 0
			buf[19] = 10

			// Recalculate checksum
			buf[10] = 0
			buf[11] = 0
			checksum := calculateHeaderChecksum(buf[:20])
			buf[10] = byte(checksum >> 8)
			buf[11] = byte(checksum & 0xff)

			// Write back to TUN
			_, err = fd.Write(buf[:n])
			if err != nil {
				fmt.Printf("TUN write error: %v\n", err)
			}
		}
	}()

	go loopInput()

	// Keep main running
	select {}
}

func loopInput() {
	for {
		var input string
		fmt.Scan(&input)
		if input == "n" {
			RouteThrowTun("vpntun", "192.168.0.10")
		}
	}
}
