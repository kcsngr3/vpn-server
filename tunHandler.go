package main

// tunHandler.go
import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	TUNSETIFF = 0x400454ca
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000 // no packet info header
)

type ifreq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte // padding
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
}

func RouteThrowTun(name string, tunIP string, serverIP string) {
	// defautlGateway := "10.2.0.1"
	// exec.Command("ip", "route", "add", serverIP+"/32", "via", defautlGateway).CombinedOutput()

	// 2. Redirect all other traffic into the TUN
	exec.Command("ip", "route", "replace", "default", "dev", name).CombinedOutput()

	exec.Command("ip", "rule", "add", "iif", "virbr0", "table", "200").CombinedOutput()
	// lan
	// exec.Command("ip", "route", "add", "default", "via", "10.0.0.254", "dev", "enp3s0", "table", "200").CombinedOutput()
	// wifi
	exec.Command("ip", "route", "add", "default", "via", "192.168.199.155", "dev", "wlp2s0", "table", "200").CombinedOutput()

	// add to RouteThrowTun after route replace
	exec.Command("resolvectl", "dns", "vpntun", "8.8.8.8").CombinedOutput()
	exec.Command("resolvectl", "domain", "vpntun", "~.").CombinedOutput()
}
func RouteThrowTunServer(name string) {
	exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward").CombinedOutput()
	exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", "192.168.0.0/24", "-o", "enp1s0", "-j", "MASQUERADE").CombinedOutput()
	exec.Command("ip", "route", "add", "192.168.0.0/24", "dev", name).CombinedOutput()
}
