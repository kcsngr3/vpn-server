package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
)

var mode = flag.String("mode", "client", "client or server")
var nicIPFlag = flag.String("nic", "10.2.0.19", "real NIC IP address")
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
	data []byte
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
	return &encapsulatedUdpPacket{data: buf}
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

func initSendSocket() {
	var err error
	sendFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal("sendFd failed:", err)
	}
	err = syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatal("IP_HDRINCL failed:", err)
	}
}

func initClientSockets() {
	initSendSocket()

	// SOCK_DGRAM owns port 51820
	// without this kernel generates ICMP unreachable locally
	// and consumes the packet before raw socket sees it
	var err error
	recvFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		log.Fatal("recvFd failed:", err)
	}
	err = syscall.Bind(recvFd, &syscall.SockaddrInet4{
		Port: 51820,
		Addr: nicIP,
	})
	if err != nil {
		log.Fatal("recvFd Bind failed:", err)
	}
}

func initServerSockets() {
	initSendSocket()

	var err error
	recvFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		log.Fatal("recvFd failed:", err)
	}
	syscall.Bind(recvFd, &syscall.SockaddrInet4{Port: 51820, Addr: nicIP})

	// claim port so kernel doesn't send ICMP unreachable
	claimFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		log.Fatal("claimFd failed:", err)
	}
	syscall.Bind(claimFd, &syscall.SockaddrInet4{Port: 51820, Addr: nicIP})
}

func initServer() {
	exec.Command("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()

	// MASQUERADE outgoing traffic on enp1s0
	// VM has no direct internet — packets go enp1s0 → virbr0(laptop) → enp3s0 → internet
	// laptop must also have MASQUERADE on enp3s0 for 192.168.122.0/24 (done in initClient)
	exec.Command("sudo", "iptables", "-t", "nat", "-F", "POSTROUTING").CombinedOutput()
	exec.Command("sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "enp1s0", "-j", "MASQUERADE").CombinedOutput()

	// Mark packets arriving on vpntun → route via table 100 → enp1s0 → internet
	exec.Command("sudo", "iptables", "-t", "mangle", "-F", "PREROUTING").CombinedOutput()
	exec.Command("sudo", "iptables", "-t", "mangle", "-A", "PREROUTING", "-i", "vpntun", "-j", "MARK", "--set-mark", "100").CombinedOutput()
	exec.Command("sudo", "ip", "rule", "del", "fwmark", "100", "table", "100").CombinedOutput()
	exec.Command("sudo", "ip", "rule", "add", "fwmark", "100", "table", "100").CombinedOutput()
	exec.Command("sudo", "ip", "route", "flush", "table", "100").CombinedOutput()
	exec.Command("sudo", "ip", "route", "add", "default", "via", "192.168.122.1", "dev", "enp1s0", "table", "100").CombinedOutput()

	// cleanup old default routes
	exec.Command("sudo", "ip", "route", "del", "default").CombinedOutput()
	exec.Command("sudo", "ip", "route", "del", "default", "dev", "vpntun").CombinedOutput()

	// VM needs a default route to reach internet via laptop (192.168.122.1 = virbr0 on laptop)
	// Without this the VM is completely isolated — ping 8.8.8.8 fails from VM
	exec.Command("sudo", "ip", "route", "add", "default", "via", "192.168.122.1", "dev", "enp1s0").CombinedOutput()

	// client NIC subnet escape route — VPN tunnel packets must not loop back into vpntun
	exec.Command("sudo", "ip", "route", "del", "10.2.0.0/16").CombinedOutput()
	exec.Command("sudo", "ip", "route", "add", "10.2.0.0/16", "via", "192.168.122.1", "dev", "enp1s0").CombinedOutput()
}

func initClient() {
	exec.Command("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	// Only iptables — zero route changes here, routes are managed by RouteThrowTun on 'n'
	exec.Command("sudo", "iptables", "-I", "INPUT", "-i", "virbr0", "-j", "ACCEPT").CombinedOutput()
	exec.Command("sudo", "iptables", "-I", "FORWARD", "-i", "virbr0", "-o", "enp3s0", "-j", "ACCEPT").CombinedOutput()
	exec.Command("sudo", "iptables", "-I", "FORWARD", "-i", "enp3s0", "-o", "virbr0",
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").CombinedOutput()
	exec.Command("sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", "192.168.122.0/24", "-o", "enp3s0", "-j", "MASQUERADE").CombinedOutput()
	fmt.Println("Client ready. Press 'n' to activate VPN routing.")
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
		initClientSockets()
	}

	if *mode == "server" {
		initServerSockets()
	}

	counter := atomic.Int64{}

	fd, name, err := OpenTUN("vpntun")
	if err != nil {
		log.Fatal("OpenTUN failed:", err)
	}

	fmt.Println("Interface:", name)

	if *mode == "client" {
		SetTUNip("vpntun", "192.168.0.10/24")
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
		SetTUNip("vpntun", "192.168.0.1/24")
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
				fmt.Printf("Src IP: %d.%d.%d.%d\n", pfull.src[0], pfull.src[1], pfull.src[2], pfull.src[3])
				fmt.Printf("Dst IP: %d.%d.%d.%d\n", pfull.dst[0], pfull.dst[1], pfull.dst[2], pfull.dst[3])
				fmt.Println("---------------------")

				mu.Lock()
				clientIP = [4]byte{buf[12], buf[13], buf[14], buf[15]}
				mu.Unlock()

				_, err = fd.Write(innerPacket)
				if err != nil {
					fmt.Printf("TUN write error: %v\n", err)
				}
			}
		}()

		// TUN → NIC
		// FIX #3: forward packets destined for the CLIENT subnet (192.168.0.x, not .1)
		// These are internet replies coming back via vpntun that need re-encapsulation
		// Old code only forwarded dst==192.168.0.1 (server itself) — that was backwards
		go func() {
			for {
				buf := make([]byte, 1500)
				n, _ := fd.Read(buf)
				if n < 20 {
					continue
				}

				// FIX #3: forward packets destined for the client TUN subnet (192.168.0.x)
				// but NOT for us (192.168.0.1) — those are local/loopback
				// Old (wrong): only forward dst == 192.168.0.1  (server's own TUN IP)
				// New (correct): forward dst == 192.168.0.x where x != 1
				if buf[16] != 192 || buf[17] != 168 || buf[18] != 0 {
					continue // not in 192.168.0.0/24 at all
				}
				if buf[19] == 1 {
					continue // that's us (192.168.0.1), skip
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
		} else if input == "n" && *mode == "server" {
			RouteThrowTunServer("vpntun")
		}
	}
}
