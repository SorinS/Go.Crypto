package main

import (
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

func main() {
	// ripemd160 Hashing
	s := "Hello 8gwifi.org"
	h := ripemd160.New()
	fmt.Println(s)
	h.Write([]byte(s))
	bs := h.Sum(nil)
	fmt.Printf("RIPEMD 160 Hash Hex Value: %x\n", bs)
}
