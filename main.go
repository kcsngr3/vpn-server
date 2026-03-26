package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
)

var mode = flag.String("mode", "client", "client or server")
var nicIPFlag = flag.String("nic", "192.168.122.1", "real NIC IP address")
var serverIP = flag.String("server", "", "VPN server IP (client mode only)")

var nicIP [4]byte
var srvIP [4]byte
var sendFd int
var recvFd int

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

type encapsulatedUdpPacket struct {
	data         []byte
	lengthOfData uint16
}

func encapsulateUdpPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) *encapsulatedUdpPacket {
	totalLen := 20 + 8 + len(payload)
	buf := make([]byte, totalLen)
	buf[0] = 0x45
	buf[1] = 0
	buf[2] = byte(totalLen >> 8)
	buf[3] = byte(totalLen)
	buf[4] = 0
	buf[5] = 0
	buf[6] = 0
	buf[7] = 0
	buf[8] = 64
	buf[9] = 17
	buf[10] = 0
	buf[11] = 0
	buf[12] = srcIP[0]
	buf[13] = srcIP[1]
	buf[14] = srcIP[2]
	buf[15] = srcIP[3]
	buf[16] = dstIP[0]
	buf[17] = dstIP[1]
	buf[18] = dstIP[2]
	buf[19] = dstIP[3]
	checksum := calculateHeaderChecksum(buf[:20])
	buf[10] = byte(checksum >> 8)
	buf[11] = byte(checksum)
	buf[20] = byte(srcPort >> 8)
	buf[21] = byte(srcPort)
	buf[22] = byte(dstPort >> 8)
	buf[23] = byte(dstPort)
	udpLen := uint16(8 + len(payload))
	buf[24] = byte(udpLen >> 8)
	buf[25] = byte(udpLen)
	buf[26] = 0
	buf[27] = 0
	copy(buf[28:], payload)
	return &encapsulatedUdpPacket{data: buf, lengthOfData: uint16(totalLen)}
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

func parseIPFlag(ipStr string) [4]byte {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		log.Fatalf("invalid IP: %s", ipStr)
	}
	parsed = parsed.To4()
	if parsed == nil {
		log.Fatalf("not an IPv4 address: %s", ipStr)
	}
	return [4]byte{parsed[0], parsed[1], parsed[2], parsed[3]}
}
func InitSockets() {
	var err error

	// sendFd: RAW socket, we provide full IP header
	sendFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal("sendFd socket:", err)
	}
	// tell kernel: I am providing my own IP header
	err = syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatal("IP_HDRINCL:", err)
	}

	// recvFd: depends on mode
	if *mode == "client" {
		// DGRAM: kernel strips headers, delivers UDP payload only
		recvFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	} else {
		// RAW: we get full packet, filter by port manually
		recvFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	}
	if err != nil {
		log.Fatal("recvFd socket:", err)
	}

	// bind recvFd to port 51820
	addr := syscall.SockaddrInet4{Port: 51820}
	err = syscall.Bind(recvFd, &addr)
	if err != nil {
		log.Fatal("Bind 51820:", err)
	}
}
func initServer() {
	InitSockets()
	SetTUNip("vpntun", "192.168.0.1/24")
}

func initClient() {
	InitSockets()
	SetTUNip("vpntun", "192.168.0.10/24")
}

func main() {
	flag.Parse()

	nicIP = parseIPFlag(*nicIPFlag)
	fmt.Printf("Mode:   %s\n", *mode)
	fmt.Printf("NIC IP: %d.%d.%d.%d\n", nicIP[0], nicIP[1], nicIP[2], nicIP[3])

	if *mode == "client" {
		if *serverIP == "" {
			log.Fatal("client mode requires -server flag")
		}
		srvIP = parseIPFlag(*serverIP)
		fmt.Printf("Server: %d.%d.%d.%d\n", srvIP[0], srvIP[1], srvIP[2], srvIP[3])

	}

	counter := atomic.Int64{}

	fd, name, err := OpenTUN("vpntun")
	if err != nil {
		log.Fatal("OpenTUN failed:", err)
	}

	fmt.Println("Interface:", name)

	if *mode == "client" {

		initClient()

		// TUN → server (outgoing)
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
				if buf[16] == 239 || buf[16] == 224 {
					continue
				}
				if buf[12] == 0 {
					continue
				}

				p := Packet{
					counter:     int(counter.Add(1)),
					packageSize: n,
					protocol:    buf[9],
					src:         [4]byte{buf[12], buf[13], buf[14], buf[15]},
					dst:         [4]byte{buf[16], buf[17], buf[18], buf[19]},
					payload:     buf[20:n],
				}
				p.displayPacket("FROM APP")

				newp := encapsulateUdpPacket(nicIP, srvIP, 51820, 51820, buf[:n])
				fmt.Printf("Encap size : %d", newp.lengthOfData)
				destAddr := &syscall.SockaddrInet4{Port: 0, Addr: srvIP}
				err = syscall.Sendto(sendFd, newp.data, 0, destAddr)
				if err != nil {
					fmt.Printf("Sendto error: %v\n", err)
				}
			}
		}()

		// server → TUN (incoming)
		// DGRAM: buf[0:n] is payload only — no IP+UDP headers
		go func() {
			for {
				buf := make([]byte, 1500)
				n, _, err := syscall.Recvfrom(recvFd, buf, 0)
				if err != nil {
					fmt.Printf("Recvfrom error: %v\n", err)
					continue
				}
				if n < 20 {
					continue
				}

				innerPacket := buf[:n] // DGRAM: no headers to strip

				p := Packet{
					counter:     int(counter.Add(1)),
					packageSize: n,
					protocol:    innerPacket[9],
					src:         [4]byte{innerPacket[12], innerPacket[13], innerPacket[14], innerPacket[15]},
					dst:         [4]byte{innerPacket[16], innerPacket[17], innerPacket[18], innerPacket[19]},
					payload:     innerPacket[20:],
				}
				p.displayPacket("TO APP")

				_, err = fd.Write(innerPacket)
				if err != nil {
					fmt.Printf("TUN write error: %v\n", err)
				}
			}
		}()
	}

	if *mode == "server" {

		fmt.Println("Server mode")
		initServer()
		var clientIP [4]byte
		var mu sync.Mutex

		// NIC → TUN
		// RAW: buf[28:n] strips IP(20)+UDP(8) headers
		go func() {
			for {
				buf := make([]byte, 1500)
				n, _, err := syscall.Recvfrom(recvFd, buf, 0)
				if err != nil {
					fmt.Printf("Recvfrom error: %v\n", err)
					continue
				}
				if n < 28 {
					continue
				}

				dstPort := uint16(buf[22])<<8 | uint16(buf[23])
				if dstPort != 51820 {
					continue
				}

				innerPacket := buf[28:n]
				if len(innerPacket) < 20 {
					continue
				}

				pfull := Packet{
					counter:     int(counter.Add(1)),
					packageSize: n,
					protocol:    buf[9],
					src:         [4]byte{buf[12], buf[13], buf[14], buf[15]},
					dst:         [4]byte{buf[16], buf[17], buf[18], buf[19]},
					payload:     buf[20:n],
				}
				pinner := Packet{
					counter:     int(counter.Add(1)),
					packageSize: n,
					protocol:    innerPacket[9],
					src:         [4]byte{innerPacket[12], innerPacket[13], innerPacket[14], innerPacket[15]},
					dst:         [4]byte{innerPacket[16], innerPacket[17], innerPacket[18], innerPacket[19]},
					payload:     innerPacket[20:],
				}
				fmt.Println("--------------------------------")
				fmt.Printf("src: %d.%d.%d.%d\n", pfull.src[0], pfull.src[1], pfull.src[2], pfull.src[3])
				fmt.Printf("dst: %d.%d.%d.%d\n", pfull.dst[0], pfull.dst[1], pfull.dst[2], pfull.dst[3])
				pinner.displayPacket("client inner packeto->internet")

				mu.Lock()
				clientIP = [4]byte{buf[12], buf[13], buf[14], buf[15]}
				mu.Unlock()

				_, err = fd.Write(innerPacket)
				if err != nil {
					fmt.Printf("TUN write error: %v\n", err)
				}
			}
		}()

		go func() {
			for {
				buf := make([]byte, 1500)
				n, _ := fd.Read(buf)
				if n < 20 {
					continue
				}

				if buf[16] != 192 || buf[17] != 168 || buf[18] != 0 {
					continue
				}
				if buf[19] == 1 {
					continue
				}

				mu.Lock()
				ip := clientIP
				mu.Unlock()

				if ip == ([4]byte{}) {
					continue
				}

				p := Packet{
					counter:     int(counter.Add(1)),
					packageSize: n,
					protocol:    buf[9],
					src:         [4]byte{buf[12], buf[13], buf[14], buf[15]},
					dst:         [4]byte{buf[16], buf[17], buf[18], buf[19]},
					payload:     buf[20:n],
				}
				p.displayPacket("TO CLIENT")

				newp := encapsulateUdpPacket(nicIP, ip, 51820, 51820, buf[:n])
				fmt.Printf("Encap size : %d", newp.lengthOfData)
				destAddr := &syscall.SockaddrInet4{Addr: ip}
				syscall.Sendto(sendFd, newp.data, 0, destAddr)
			}
		}()
	}

	go loopInput()
	select {}
}

func loopInput() {
	for {
		var input string
		fmt.Scan(&input)
		if input == "n" && *mode == "client" {
			RouteThrowTun("vpntun", "192.168.0.10", *serverIP)
			fmt.Print("Routing on")
		} else if input == "n" && *mode == "server" {
			RouteThrowTunServer("vpntun")
		}
	}
}
