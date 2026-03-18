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
	// Step 1: read current default gateway BEFORE touching any routes
	// This is the real gateway (e.g. 10.2.0.1 via enp3s0)
	gwOut, _ := exec.Command("ip", "route", "show", "default").Output()
	gw, dev := "", ""
	fmt.Sscanf(string(gwOut), "default via %s dev %s", &gw, &dev)
	fmt.Printf("Gateway: %s dev %s\n", gw, dev)

	if gw == "" || dev == "" {
		fmt.Println("ERROR: could not read default gateway, aborting route setup")
		return
	}

	// Step 2: server /32 escape route via real gateway
	// This MUST exist before adding default dev vpntun
	// Without it, tunnel UDP to server also enters vpntun -> infinite loop
	exec.Command("sudo", "ip", "route", "del", serverIP+"/32").CombinedOutput()
	out, err := exec.Command("sudo", "ip", "route", "add", serverIP+"/32",
		"via", gw, "dev", dev, "metric", "0").CombinedOutput()
	fmt.Printf("server escape route: %s %v\n", string(out), err)

	// Step 3: add default via vpntun
	// 192.168.122.0/24 already exists as kernel route via virbr0 — DO NOT touch it
	// server /32 already set above — wins by longest prefix
	// so only internet traffic enters vpntun
	exec.Command("sudo", "ip", "route", "del", "default", "dev", name).CombinedOutput()
	out, err = exec.Command("sudo", "ip", "route", "add", "default",
		"dev", name, "metric", "1").CombinedOutput()
	fmt.Printf("default vpntun route: %s %v\n", string(out), err)

	fmt.Println("VPN routing active.")
}

func RouteThrowTunServer(name string) {
	// server routing is handled entirely by initServer() + fwmark table 100
	// nothing needed here
}
