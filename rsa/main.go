package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
)

func main() {
	pk, err := RSA(2048)
	if err != nil {
		fmt.Printf("error RSA 2048: %v\n", err.Error)
		os.Exit(1)
	}
	fmt.Println("RSA 2048 Private Key ", *pk)
	fmt.Println("RSA 2048 Public Key ", pk.PublicKey)
}

func RSA(size int) (*rsa.PrivateKey, error) {
	// Generate Alice RSA keys Of 2048 Buts
	aPrivateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}
	// Extract Public Key from RSA Private Key
	return aPrivateKey, nil
}
