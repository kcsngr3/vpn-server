package main

import (
	"crypto/aes"
	"fmt"
	"math/rand"

	"crypto/cipher"
)

type encryptHandler struct {
	aead cipher.AEAD
}

func initEncryptHandler(key [32]byte) *encryptHandler {
	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)
	return &encryptHandler{aead: aead}
}
func (eh *encryptHandler) encryptPlain(plainData []byte) []byte {
	Nonce := make([]byte, eh.aead.NonceSize())
	rand.Read(Nonce)
	return eh.aead.Seal(Nonce, Nonce, plainData, nil)

}
func (eh *encryptHandler) encryptPacket(plainData []byte, sessionId string) []byte {
	Nonce := make([]byte, eh.aead.NonceSize())
	rand.Read(Nonce)
	return eh.aead.Seal(Nonce, Nonce, plainData, []byte(sessionId))

}
func (eh *encryptHandler) decrypt(encrypted []byte) ([]byte, error) {
	nonce := encrypted[:eh.aead.NonceSize()]
	plaintext, err := eh.aead.Open(nil, nonce, encrypted[eh.aead.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return plaintext, nil
}
func (eh *encryptHandler) decryptPacket(encrypted []byte, sessionId string) ([]byte, error) {
	nonce := encrypted[:eh.aead.NonceSize()]
	plaintext, err := eh.aead.Open(nil, nonce, encrypted[eh.aead.NonceSize():], []byte(sessionId))
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return plaintext, nil
}
