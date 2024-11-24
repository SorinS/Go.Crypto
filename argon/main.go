package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
)

func main() {
	pwd := "my secret Password"
	Argon2Key(pwd)
	Argos2ID(pwd)
}

func Argon2Key(pwd string) {
	m := 32 * 1024
	keyLen := 32
	// Generatign Random Salt of 8 byte
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.Key([]byte(pwd), salt, 3, uint32(m), 4, uint32(keyLen))
	fmt.Println("Argon2 Derive Key of length 32 Base64 Value: ", base64.StdEncoding.EncodeToString(key))
}

func Argos2ID(pwd string) {
	m := 64 * 1024
	keyLen := 32
	// Generatign Random Salt of 8 byte
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte(pwd), salt, 1, uint32(m), 4, uint32(keyLen))
	fmt.Println("Argon2 IDkey of length 32 Base64 Value: ", base64.StdEncoding.EncodeToString(key))
}
