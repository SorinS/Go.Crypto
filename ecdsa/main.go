package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	// Message to Be signed and Verify
	secretMessage := "Hello 8gwifi.org"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Error Generating Parameter %s", err)
		os.Exit(1)
	}
	var pubkey ecdsa.PublicKey
	pubkey = priv.PublicKey

	// In production DONOT Log this Key, keep it safe and Secure.
	fmt.Printf("Private Key :%x \n", *priv)
	fmt.Printf("Public Key %x \n:", pubkey)
	// Always Sign the Hash of the Message
	hashed := sha256.Sum256([]byte(secretMessage))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		fmt.Println("Error signing: %s", err)
		return
	}
	fmt.Printf("signature: (0x%x, 0x%x)\n", r, s)
	if !ecdsa.Verify(&pubkey, hashed[:], r, s) {
		fmt.Println("Error Verification ", err)
		return
	}
	fmt.Println("Signature Verification Passed ")
}
