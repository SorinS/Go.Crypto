package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

func main() {
	password := "myverystrongpassword"
	iter := 10000 // Iteration Count
	size := 10    // Output Length
	length := 10
	// Generate Random Salt Value size := 10
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	o := pbkdf2.Key([]byte(password), []byte(salt), iter, length, sha1.New)
	fmt.Printf("PBKDF2 sha1 Hash Value : %x\n", o)
	o = pbkdf2.Key([]byte(password), []byte(salt), iter, length, sha512.New)
	fmt.Printf("PBKDF2 SHA-512 Hash Value : %x\n", o)
	o = pbkdf2.Key([]byte(password), []byte(salt), iter, length, md5.New)
	fmt.Printf("PBKDF2 MD5 Hash Value : %x\n", o)
	o = pbkdf2.Key([]byte(password), []byte(salt), iter, length, ripemd160.New)
	fmt.Printf("PBKDF2 RIPEMD Hash Value : %x\n", o)
}
