package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"log"
)

func main() {
	password := "myverystrongpassword-8gwifi.org"
	N := 1 << 15
	r := 8
	p := 2
	keyLen := 32
	// generate random salt. 8 bytes is a good length.
	c := 8
	salt := make([]byte, c)
	_, err := rand.Read(salt)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	dk, err := scrypt.Key([]byte(password), salt, N, r, p, keyLen)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(dk))
}
