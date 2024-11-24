package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"os"
)

func main() {
	Example1()
	fmt.Println()
	Example1()

}

func Example1() {
	// Underlying hash function for HMAC.
	hash := sha256.New

	// Cryptographically secure master secret.
	master := []byte{0x00, 0x01, 0x02, 0x03} //use your own master key

	// This Master key will split into three Crypto Key
	// Non-secret salt, optional (can be nil). Recommended: hash-length random value.
	salt := make([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	// Non-secret context info, optional (can be nil).
	info := []byte{}
	// info := []byte{"Hello 8gwifi.org"}

	// Generate three 128-bit derived keys.
	hk := hkdf.New(hash, master, salt, info)
	var keys [][]byte
	for i := 0; i < 3; i++ {
		key := make([]byte, 16)
		if _, err := io.ReadFull(hk, key); err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(2)
		}
		keys = append(keys, key)
		fmt.Printf("HKDF Key #%d: %x\n", i+1, key)
		for i := range keys {
			fmt.Printf("Key #%d: %v\n", i+1, !bytes.Equal(keys[i], make([]byte, 16)))
		}
	}
}

func Example2() {
	hash := sha1.New
	master := []byte{0x00, 0x01, 0x02, 0x03}
	info := []byte{}
	salt := make([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	// Generate Pesudo random
	prk := hkdf.Extract(hash, master, salt)
	fmt.Printf("PRK %x\n", prk)
	// Generate 3 Secret Key from the given Master key and PRK
	hkdf := hkdf.Expand(hash, prk, info)
	var keys [][]byte

	for i := 0; i < 3; i++ {
		key := make([]byte, 16)
		if _, err := io.ReadFull(hkdf, key); err != nil {
			panic(err)
		}
		keys = append(keys, key)
		fmt.Printf("HKDF Key #%d: %x\n", i+1, key)
	}
	for i := range keys {
		fmt.Printf("Key #%d: %v\n", i+1, !bytes.Equal(keys[i], make([]byte, 16)))
	}
}
