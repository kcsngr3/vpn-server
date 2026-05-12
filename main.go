package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var mode = flag.String("mode", "client", "client or server")
var globalServer *Server
var globalClient *Client

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

	cfg, err := loadConfig("config.conf")
	if err != nil {
		log.Fatal("config load failed:", err)
	}

	fd, name, err := OpenTUN("vpntun")
	if err != nil {
		log.Fatal("OpenTUN failed:", err)
	}
	fmt.Println("Interface:", name)

	switch *mode {
	case "client":
		serverIP := cfg.Client.ServerIP
		if serverIP == "" {
			log.Fatal("client config requires server_ip")
		}

		fmt.Printf("Mode:   client\n")
		fmt.Printf("Server: %s\n", serverIP)

		c := &Client{}

		ipEnd, err := SendAuth(c, serverIP)
		if err != nil {
			log.Fatal("Auth failed:", err)
		}

		c.conn = initClient(fmt.Sprintf("192.168.0.%d", ipEnd), serverIP)
		c.fd = fd
		c.vpnIpEnd = byte(ipEnd)
		c.serverToClient = initTrafficTracker()
		c.clientToServer = initTrafficTracker()
		globalClient = c
		c.Run()

		go loopInput()
		select {}

	case "server":
		nicIP := cfg.Server.NicIP
		if nicIP == "" {
			nicIP, err = getGCloudNicIP()
			if err != nil {
				log.Fatal("nic_ip not set and gcloud metadata failed:", err)
			}
		}

		fmt.Printf("Mode:     server\n")
		fmt.Printf("NIC IP:   %s\n", nicIP)
		fmt.Printf("Region:   %s\n", cfg.Server.Region)
		fmt.Printf("ServerID: %s\n", cfg.Server.ServerID)

		db, err := initDb(cfg.Server.DbURL, cfg.Server.ServerID, cfg.Server.Region)
		if err != nil {
			log.Fatal("DB init failed:", err)
		}

		errInitDb := db.TxInitServer(cfg.Server.ServerID, nicIP, cfg.Server.Region)
		if errInitDb != nil {
			log.Fatal("DB server init failed:", errInitDb)
		}

		s := &Server{
			fd:      fd,
			ippool:  newIPPool(),
			session: make(map[byte]*ClientSession),
			db:      db,
		}
		s.conn = initServer(cfg.Server.TunIP)
		globalServer = s

		s.Run()
		RouteThrowTunServer("vpntun")
		ListenAuth(s)
		s.ListenHeartBeatServer()
		go s.goWatchTimeOut()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go loopInput()

		<-sigChan
		fmt.Println("Shutting down — closing all sessions...")
		s.closeAllSessions()
		db.Close()
		fmt.Println("Done.")

	default:
		log.Fatal("unknown mode — use -mode=client or -mode=server")
	}
}

func loopInput() {
	for {
		var input string
		fmt.Scan(&input)
		if input == "n" && *mode == "client" {
			cfg, _ := loadConfig("config.conf")
			RouteThrowTun("vpntun", "192.168.0."+string(globalClient.vpnIpEnd), cfg.Client.ServerIP)
			fmt.Println("Routing on")
		}
		if input == "l" && *mode == "server" {
			globalServer.listAllSessionTraffic()
		}
	}
}
