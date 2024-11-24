package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const key = "myverystrongpasswordo32bitlength"

func main() {
	plainText := "Hello 8gwifi.org"
	ct, err := AESEncrypt([]byte(key), plainText)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Original Text: %s\n", plainText)
	fmt.Printf("AES Encrypted Text: %s\n", ct)
	dc, err := AESDecrypt([]byte(key), ct)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(2)
	}
	fmt.Printf("AES Decrypted Text: %s\n", dc)
	fmt.Println("====File Encryption/ Decryption====")
	infileName := "hello.txt"
	encfileName := "hello.txt.enc"
	decfileName := "hello.txt.dec"
	if err := AESFileEncrypt(key, infileName, encfileName); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(3)
	}
	if err := AESFileDecrypt(key, encfileName, decfileName); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(4)
	}
}

func AESEncrypt(key []byte, plaintext string) (string, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(plaintext))
	c.Encrypt(out, []byte(plaintext))
	return hex.EncodeToString(out), nil
}

func AESDecrypt(key []byte, ct string) (string, error) {
	ciphertext, _ := hex.DecodeString(ct)
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plain := make([]byte, len(ciphertext))
	c.Decrypt(plain, ciphertext)
	return string(plain[:]), nil
}

func AESFileEncrypt(key string, infileName string, encfileName string) error {
	inFile, err := os.Open(infileName)
	if err != nil {
		return err
	}
	defer inFile.Close()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	// If the key is unique for each ciphertext, then it's ok to use a zero IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	outFile, err := os.OpenFile(encfileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer outFile.Close()
	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		return err
	}

	return nil
}

func AESFileDecrypt(key string, encfileName string, decfileName string) error {
	inFile, err := os.Open(encfileName)
	if err != nil {
		return err
	}
	defer inFile.Close()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	// If the key is unique for each ciphertext, then it's ok to use a zero IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	outFile, err := os.OpenFile(decfileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()
	reader := &cipher.StreamReader{S: stream, R: inFile}
	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(outFile, reader); err != nil {
		return err
	}
	return nil
}
