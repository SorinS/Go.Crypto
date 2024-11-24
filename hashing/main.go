package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/sha3"
)

func main() {
	s := "Hello 8gwifi.org"
	fmt.Printf("Hashing %s\n", s)

	fmt.Printf("SHA1 Hex : %x\n", SHA1Hash(s))
	fmt.Printf("SHA512 Hex : %x\n", SHA512Hash(s))
	fmt.Printf("SHA512-384 Hex : %x\n", SHA512_384Hash(s))
	fmt.Printf("SHA3-224 Hex : %x\n", SHA3_224Hash(s))
	fmt.Printf("SHA3-384 Hex : %x\n", SHA3_384Hash(s))
	fmt.Printf("SHA3-512 Hex : %x\n", SHA3_512Hash(s))
	fmt.Printf("MD5 Hex: %x\n", MD5Hash(s))
}

func MD5Hash(s string) []byte {
	h := md5.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return bs
}

func SHA1Hash(s string) []byte {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return bs
}

func SHA512Hash(s string) []byte {
	h := sha512.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return bs
}

func SHA512_384Hash(s string) []byte {
	h := sha512.New384()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return bs
}

func SHA3_224Hash(s string) []byte {
	h := sha3.New224()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return bs
}

func SHA3_384Hash(s string) []byte {
	h := sha3.New384()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func SHA3_512Hash(s string) []byte {
	h := sha3.New512()
	h.Write([]byte(s))
	return h.Sum(nil)
}
