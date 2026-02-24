package main

import (
	"fmt"
	"log"
	"os/exec"
)

func main() {
	fd, name, err := OpenTUN("vpntun")
	if err != nil {
		log.Fatal("OpenTUN failed:", err)
	}

	// check each command
	out, err := exec.Command("ip", "addr", "add", "10.0.0.101/24", "dev", name).CombinedOutput()
	fmt.Println("addr add:", string(out), err)

	out, err = exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	fmt.Println("link up:", string(out), err)

	fmt.Println("Interface:", name)

	buf := make([]byte, 1500)
	counter := 1
	for {
		n, err := fd.Read(buf)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Time %d\n", counter)
		fmt.Printf("Got packet: %d bytes\n", n)
		fmt.Printf("Protocol: %d\n", buf[9])
		fmt.Printf("Src IP: %v\n", buf[12:16])
		fmt.Printf("Dst IP: %v\n", buf[16:20])
		fmt.Printf("Payload: %x\n", buf[28:n])
		fmt.Printf("Payload: %d\n", buf[28:n])
		counter++
	}
}
