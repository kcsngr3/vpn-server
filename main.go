package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync/atomic"
)

var mode = flag.String("mode", "client", "client or server")
var nicIPFlag = flag.String("nic", "192.168.122.1", "real NIC IP address")
var serverIP = flag.String("server", "", "VPN server IP (client mode only)")
var globalServer *Server

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

func main() {
	flag.Parse()

	nicIP := parseIPFlag(*nicIPFlag)
	fmt.Printf("Mode:   %s\n", *mode)
	fmt.Printf("NIC IP: %d.%d.%d.%d\n", nicIP[0], nicIP[1], nicIP[2], nicIP[3])

	fd, name, err := OpenTUN("vpntun")
	if err != nil {
		log.Fatal("OpenTUN failed:", err)
	}
	fmt.Println("Interface:", name)

	counter := &atomic.Int64{}

	switch *mode {
	case "client":
		if *serverIP == "" {
			log.Fatal("client mode requires -server flag")
		}
		srvIP := parseIPFlag(*serverIP)
		fmt.Printf("Server: %d.%d.%d.%d\n", srvIP[0], srvIP[1], srvIP[2], srvIP[3])

		// declare empty client first
		c := &Client{}

		// auth — passes empty client, fills eh inside
		ipEnd, err := SendAuth(c, *serverIP)
		if err != nil {
			log.Fatal("Auth failed:", err)
		}

		// now build the rest
		sendFd, recvFd := initClient(fmt.Sprintf("192.168.0.%d", ipEnd))
		c.fd = fd
		c.nicIP = nicIP
		c.srvIP = srvIP
		c.sendFd = sendFd
		c.recvFd = recvFd
		c.counter = counter
		//eh set in the auth fase

		c.Run()
	case "server":
		fmt.Println("Server mode")
		RouteThrowTunServer("vpntun")
		sendFd, recvFd := initServer()
		s := &Server{
			fd:               fd,
			nicIP:            nicIP,
			sendFd:           sendFd,
			recvFd:           recvFd,
			ippool:           newIPPool(),
			session:          make(map[byte]*ClientSession), // ADD
			dstIpToSessionId: make(map[byte]byte),           // ADD
		}
		globalServer = s
		s.Run()
		ListenAuth(s)

	default:
		panic("unrecognized escape character")
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
		} else if input == "l" && *mode == "server" {
			globalServer.ippool.listIPPool()
		}
	}
}
