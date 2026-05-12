package main

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
)

type encapsulatedUdpPacket struct {
	data         []byte
	lengthOfData uint16
}
type trafficTracker struct {
	mu             sync.Mutex
	highestId      uint64
	window         uint64 // bitmask of received ID
	windowSize     uint64
	droppedTraffic atomic.Uint64
}

func initTrafficTracker() *trafficTracker {
	return &trafficTracker{highestId: 0, window: 0, windowSize: 64, droppedTraffic: atomic.Uint64{}}
}

func (t *trafficTracker) incrementId() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.highestId++
	return t.highestId
}
func (t *trafficTracker) verifyId(idx uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx > t.highestId {
		// advance window
		shift := idx - t.highestId
		t.window <<= shift
		t.window |= 1
		t.highestId = idx
		return true
	}
	diff := t.highestId - idx
	if diff >= t.windowSize {
		t.droppedTraffic.Add(1)
		return false // too old
	}
	bit := uint64(1) << diff
	if t.window&bit != 0 {
		t.droppedTraffic.Add(1)
		return false // duplicate
	}
	t.window |= bit
	return true
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

func encapsulatePacket(idxPacket uint64, vpnIpEnd byte, payload []byte) []byte {
	encPacketSlice := make([]byte, 9+len(payload))
	encPacketSlice[0] = vpnIpEnd
	binary.BigEndian.PutUint64(encPacketSlice[1:9], idxPacket)
	copy(encPacketSlice[9:], payload)
	return encPacketSlice
}
func decapsulatesPacket(encapPayload []byte, n int) (idxPacket uint64, vpnIpEnd byte, payload []byte) {

	vpnIP := encapPayload[0]
	idxS := binary.BigEndian.Uint64(encapPayload[1:9])
	encrypted := encapPayload[9:n]
	return idxS, byte(vpnIP), encrypted
}

//
