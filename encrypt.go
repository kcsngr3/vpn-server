package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"crypto/cipher"
)

type encryptHandler struct {
	aead cipher.AEAD
	key  [32]byte
}

func initEncryptHandler(key [32]byte) *encryptHandler {
	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)
	return &encryptHandler{aead: aead, key: key}
}
func (eh *encryptHandler) encryptPlain(plainData []byte) []byte {
	Nonce := make([]byte, eh.aead.NonceSize())
	rand.Read(Nonce)
	return eh.aead.Seal(Nonce, Nonce, plainData, nil)

}
func (eh *encryptHandler) encryptPacket(plainData []byte, idxPacket uint64, VpnIpEnd byte) []byte {
	Nonce := make([]byte, eh.aead.NonceSize())
	rand.Read(Nonce)
	return eh.aead.Seal(Nonce, Nonce, plainData, binary.BigEndian.AppendUint64([]byte{VpnIpEnd}, idxPacket))

}
func (eh *encryptHandler) decrypt(encrypted []byte) ([]byte, error) {
	nonce := encrypted[:eh.aead.NonceSize()]
	plaintext, err := eh.aead.Open(nil, nonce, encrypted[eh.aead.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return plaintext, nil
}
func (eh *encryptHandler) decryptPacket(encrypted []byte, idxPacket uint64, VpnIpEnd byte) ([]byte, error) {
	nonce := encrypted[:eh.aead.NonceSize()]
	plaintext, err := eh.aead.Open(nil, nonce, encrypted[eh.aead.NonceSize():], binary.BigEndian.AppendUint64([]byte{VpnIpEnd}, idxPacket))
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return plaintext, nil
}
