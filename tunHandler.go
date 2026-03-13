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
	// 1. open the tun device
	fd, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}

	// 2. configure it via ioctl
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = IFF_TUN | IFF_NO_PI

	// 3. ioctl syscall — tells kernel "give me a TUN interface"
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
	// check each command
	out, err := exec.Command("ip", "addr", "add", ip, "dev", name).CombinedOutput()
	fmt.Println("addr add:", string(out), err)

	out, err = exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	fmt.Println("link up:", string(out), err)

}
func RouteThrowTun(name string, ip_NoMASK string) {

	// Route all traffic through TUN
	// out, err := exec.Command("sudo", "ip", "route", "add", "0.0.0.0/0", "via", ip_NoMASK, "dev", name).CombinedOutput()
	// fmt.Println("route add:", string(out), err)
	out, err := exec.Command("sudo", "ip", "route", "add", "default", "dev", name, "metric", "1").CombinedOutput()
	fmt.Println("route add:", string(out), err)
	out, err = exec.Command("sudo", "ip", "route", "add", "10.0.0.254", "via", "10.0.0.254", "dev", "enp3s0", "metric", "0").CombinedOutput()
	fmt.Println("route add:", string(out), err)
}
