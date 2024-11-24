package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
	msg := "https://8gwifi.org"
	ExampleURLEncode(msg)
	ExampleStdEncoding(msg)
}

func ExampleURLEncode(msg string) {
	// Base64 Encoding
	encmess := base64.URLEncoding.EncodeToString([]byte(msg))
	fmt.Println("Base64 Encoded Message", encmess)
	// Base64 Decoding
	decode, err := base64.URLEncoding.DecodeString(encmess)
	if err != nil {
		fmt.Println("Failed to Perform URL Encoding", encmess)
		return
	}
	fmt.Println("Base64 Decoded Message", string(decode))
}

func ExampleStdEncoding(msg string) {
	// Base64 Encoding
	encmess := base64.StdEncoding.EncodeToString([]byte(msg))
	fmt.Println("Base64 Encoded Message", encmess)
	// Base64 Decoding
	decode, err := base64.StdEncoding.DecodeString(encmess)
	if err != nil {
		fmt.Println("Falied to Perfrom URL Encoding", encmess)
		return
	}
	fmt.Println("Base64 Decoded Message", string(decode))

}
