package main

import (
	"fmt"
)

type Packet struct {
	protocol    byte
	src         [4]byte
	dst         [4]byte
	payload     []byte
	packageSize int
	counter     int
}
type encapsulatedUdpPacket struct {
	data         []byte
	lengthOfData uint16
}

func displayPacket(note string, buf []byte, buffSize int, showInner int) {
	if buffSize < 20 {
		return
	}
	dst0 := buf[16]
	if dst0 == 239 || dst0 == 240 || dst0 == 224 {
		return
	}

	fmt.Println(note)
	fmt.Printf("Src IP:   %d.%d.%d.%d\n", buf[12], buf[13], buf[14], buf[15])
	fmt.Printf("Dst IP:   %d.%d.%d.%d\n", buf[16], buf[17], buf[18], buf[19])
	fmt.Printf("Protocol: %d\n", buf[9])
	fmt.Printf("Size:     %d bytes\n", buffSize)
	fmt.Printf("Payload:  %x\n", buf[20:buffSize])

	if showInner == 1 {
		if buffSize < 48 {
			fmt.Println("  [inner] packet too small")
			return
		}
		inner := buf[28:buffSize]
		fmt.Printf("  [inner] Src IP: %d.%d.%d.%d\n", inner[12], inner[13], inner[14], inner[15])
		fmt.Printf("  [inner] Dst IP: %d.%d.%d.%d\n", inner[16], inner[17], inner[18], inner[19])
	}
}
func encapsulateUdpPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte, sessionId byte) *encapsulatedUdpPacket {
	tagged := make([]byte, 1+len(payload))
	tagged[0] = sessionId
	copy(tagged[1:], payload)
	totalLen := 20 + 8 + len(tagged)
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
	udpLen := uint16(8 + len(tagged))
	buf[24] = byte(udpLen >> 8)
	buf[25] = byte(udpLen)
	buf[26] = 0
	buf[27] = 0
	copy(buf[28:], tagged)
	return &encapsulatedUdpPacket{data: buf, lengthOfData: uint16(totalLen)}
}
func decapsulateUdpPacket(encapPacket []byte) (innerPacket []byte, sessionId byte) {
	payload := encapPacket[28:]
	sessionId = payload[0] // 1 byte, no string, no hex
	innerPacket = payload[1:]
	return
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
