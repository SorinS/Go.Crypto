package main

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"io"
)

func main() {
	alicePublicKey, _, _ := GenerateKey(rand.Reader)
	_, bobPrivateKey, _ := GenerateKey(rand.Reader)
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, alicePublicKey, bobPrivateKey)
	result := fmt.Sprintf("%x", sharedKey[:])
	fmt.Println("Arrived Secret Key ", result)
}

func GenerateKey(rand io.Reader) (publicKey, privateKey *[32]byte, err error) {
	publicKey = new([32]byte)
	privateKey = new([32]byte)
	_, err = io.ReadFull(rand, privateKey[:])
	if err != nil {
		publicKey = nil
		privateKey = nil
		return
	}
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return
}
