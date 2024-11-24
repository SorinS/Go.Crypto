package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

// Specs
// https://blake2.net/blake2.pdf
// https://blake2.net/blake2x.pdf

func main() {
	s := "Hello 8gwifi.org"
	fmt.Printf("Hashing: %s\n", s)
	ExampleBlake2bHash(s)
	fmt.Println("-------------------------------------------------")
	ExampleBlake2sHash(s)

}

func ExampleBlake2bHash(s string) {
	// Blake2b Hashing
	h := blake2b.Sum256([]byte(s))
	fmt.Printf("Blake2b Sum256 Hex Value : %x\n", h)
	h384 := blake2b.Sum384([]byte(s))
	fmt.Printf("Blake2b Sum284 Hex Value : %x\n", h384)
	h512 := blake2b.Sum512([]byte(s))
	fmt.Printf("Blake2b Sum512 Hex Value : %x\n", h512)

	// Blake2b Hashing 256 with HMAC
	key := make([]byte, 64)
	hk, _ := blake2b.New256(key)
	hk.Write([]byte(s))
	bs := hk.Sum(nil)
	fmt.Printf("Blake2b HMAC Key 256 Hash Hex Value: %x\n", bs)

	// Blake2b Hashing 384 with HMAC
	key = make([]byte, 64)
	hk, _ = blake2b.New384(key)
	hk.Write([]byte(s))
	bs = hk.Sum(nil)
	fmt.Printf("Blake2b HMAC Key 384 Hash Hex Value: %x\n", bs)

	// Blake2b Hashing 512 with HMAC
	key = make([]byte, 64)
	hk, _ = blake2b.New512(key)
	hk.Write([]byte(s))
	bs = hk.Sum(nil)
	fmt.Printf("Blake2b HMAC Key 512 Hash Hex Value: %x\n", bs)
}

func ExampleBlake2sHash(s string) {
	// Blake2s Hashing
	h := blake2s.Sum256([]byte(s))
	fmt.Printf("Blake2s Sum256 Hex Value : %x\n", h)

	// Blake2s Hashing with HMAC
	key, _ := hex.DecodeString("7a844e79904ae63e14327d8fb0749bdb8638ad435e42c01d4e294b0eb6bda0fb")
	hk, err := blake2s.New256(key)
	if err != nil {
		fmt.Printf("#%d: error from New256: %v", err)
	}
	hk.Write([]byte(s))
	bs := hk.Sum(nil)
	fmt.Printf("Blake2s HMAC Key 256 Hash Hex Value: %x\n", bs)
}
