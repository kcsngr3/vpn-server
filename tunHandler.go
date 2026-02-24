package main

// tunHandler.go
import (
	"os"
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
