package main

import (
	"fmt"
	"log"
	"sync/atomic"
	"syscall"
)

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

func main() {
	counter := atomic.Int64{}

	fd, name, err := OpenTUN("vpntun")
	if err != nil {
		log.Fatal("OpenTUN failed:", err)
	}
	SetTUNip("vpntun", "192.168.0.10/24")
	fmt.Println("Interface:", name)

	// Create raw socket
	rawFd, err := syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_RAW,
		syscall.IPPROTO_RAW,
	)
	if err != nil {
		log.Fatal("Socket creation failed:", err)
	}
	// defer syscall.Close(rawFd)

	// Allow custom IP headers
	err = syscall.SetsockoptInt(rawFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatal("SetsockoptInt failed:", err)
	}
	err = syscall.SetsockoptString(rawFd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "enp3s0")
	if err != nil {
		log.Fatal("SO_BINDTODEVICE failed:", err)
	}
	// Bind to physical NIC
	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{10, 0, 0, 101}, // your real NIC IP
	}
	err = syscall.Bind(rawFd, &addr)
	if err != nil {
		log.Fatal("Bind failed:", err)
	}

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

			// Rewrite source IP to your real NIC IP (10.2.0.52)
			buf[12] = 10
			buf[13] = 2
			buf[14] = 0
			buf[15] = 52

			// Recalculate checksum
			buf[10] = 0
			buf[11] = 0
			checksum := calculateHeaderChecksum(buf[:20])
			buf[10] = byte(checksum >> 8)
			buf[11] = byte(checksum & 0xff)

			// Extract destination IP from packet
			destAddr := syscall.SockaddrInet4{
				Port: 0,
				Addr: [4]byte{buf[16], buf[17], buf[18], buf[19]},
			}

			// Send to real NIC
			err = syscall.Sendto(rawFd, buf[:n], 0, &destAddr)
			if err != nil {
				fmt.Printf("Sendto error: %v\n", err)
			}
		}
	}()

	// Real NIC → TUN (incoming traffic)
	go func() {
		for {
			buf := make([]byte, 1500)

			// Receive from raw socket
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

			// Create packet struct for display
			p := Packet{
				counter:     int(counter.Add(1)),
				packageSize: n,
				protocol:    buf[9],
				src:         [4]byte{buf[12], buf[13], buf[14], buf[15]},
				dst:         [4]byte{buf[16], buf[17], buf[18], buf[19]},
				payload:     buf[20:n],
			}
			p.displayPacket("vpn->app")

			// Rewrite destination IP back to TUN IP (10.0.0.x)
			// Keep the original destination that was modified from TUN
			buf[16] = 10
			buf[17] = 0
			buf[18] = 0
			buf[19] = 101 // or whatever TUN client IP was

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
