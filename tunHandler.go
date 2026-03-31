package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	TUNSETIFF = 0x400454ca
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

type ifreq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

func OpenTUN(name string) (*os.File, string, error) {
	fd, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}

	var req ifreq
	copy(req.Name[:], name)
	req.Flags = IFF_TUN | IFF_NO_PI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd.Fd(),
		TUNSETIFF,
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return nil, "", errno
	}

	return fd, strings.TrimRight(string(req.Name[:]), "\x00"), nil
}

func SetTUNip(name string, ip string) {
	out, err := exec.Command("ip", "addr", "add", ip, "dev", name).CombinedOutput()
	fmt.Println("addr add:", string(out), err)

	out, err = exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	fmt.Println("link up:", string(out), err)

	exec.Command("ip", "link", "set", name, "mtu", "1200").CombinedOutput()
}

// initSockets is shared by both client and server.
// mode = "client" → recvFd is SOCK_DGRAM (kernel strips headers)
// mode = "server" → recvFd is SOCK_RAW  (full packet, manual port filter)
func initSockets(mode string) (sendFd int, recvFd int) {
	var err error

	sendFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal("sendFd socket:", err)
	}
	err = syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatal("IP_HDRINCL:", err)
	}

	if mode == "client" {
		recvFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	} else {
		recvFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	}
	if err != nil {
		log.Fatal("recvFd socket:", err)
	}

	addr := syscall.SockaddrInet4{Port: 51820}
	if err = syscall.Bind(recvFd, &addr); err != nil {
		log.Fatal("Bind 51820:", err)
	}

	return sendFd, recvFd
}

func RouteThrowTun(name string, tunIP string, serverIP string) {
	// virbr0 kernel route already handles 192.168.122.x — no /32 needed
	// just replace default, virbr0 subnet wins automatically
	iface := getDefaultInterface()
	gw := getDefaultGateway()
	dns := getCurrentDNS()
	fmt.Printf("Iface: %s\nGateway: %s\nDns: %s\n", iface, gw, dns)
	exec.Command("ip", "route", "replace", "default", "dev", name).CombinedOutput()

	exec.Command("ip", "rule", "add", "iif", "virbr0", "table", "200").CombinedOutput()
	exec.Command("ip", "route", "add", "default", "via", gw,
		"dev", iface, "table", "200").CombinedOutput()

	exec.Command("resolvectl", "dns", name, dns).CombinedOutput()
	exec.Command("resolvectl", "domain", name, "~.").CombinedOutput()
}

func RouteThrowTunServer(name string) {
	iface := getDefaultInterface()
	exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward").CombinedOutput()
	exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", "192.168.0.0/24", "-o", iface, "-j", "MASQUERADE").CombinedOutput()
	exec.Command("ip", "route", "add", "192.168.0.0/24", "dev", name).CombinedOutput()
}
func getDefaultGateway() string {
	out, _ := exec.Command("ip", "route", "show", "default").Output()
	fields := strings.Fields(string(out))
	if len(fields) >= 3 {
		return fields[2]
	}
	return ""
}

func getDefaultInterface() string {
	out, _ := exec.Command("ip", "route", "show", "default").Output()
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func getCurrentDNS() string {
	out, _ := exec.Command("resolvectl", "status", "--no-pager").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "DNS Servers") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2]
			}
		}
	}
	return getDefaultGateway() // fallback to gateway as DNS
}
