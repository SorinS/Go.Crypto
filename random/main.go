package main

import (
	"crypto/rand"
	"fmt"
)

func main() {
	// First Example without Make Method
	key := [10]byte{}
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}
	fmt.Println(key)

	// Second Example with make this is mostly Used for Generating IV values
	c := 10
	b := make([]byte, c)
	_, err = rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(b)
}
