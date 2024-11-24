package main

import (
	"crypto/rand"
	crypto_rand "crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/auth"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
	"os"
)

const key = "myverystrongpasswordo32bitlengt"

func main() {
	message := "Hello 8gwifi.org using go lang Box Example"
	if err := NACL(message); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if err := NACLFast(message); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(2)
	}

	if err := NACLSecretBox(message); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(3)
	}

	NACLAuth(message)
	NACLSign(message)
}

func NACL(message string) error {
	pkalice, skalice, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return err
	}

	pkbob, skbob, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return err
	}

	fmt.Printf("Original Text: %s\n", message)
	fmt.Println("====NACL Box Seal/ Open====")

	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(crypto_rand.Reader, nonce[:]); err != nil {
		return err
	}

	// This encrypts msg and appends the result to the nonce.
	encrypted := box.Seal(nonce[:], []byte(message), &nonce, pkbob, skalice)
	fmt.Printf("Alice Send Encrypted Message to Bob %x\n", encrypted)
	// The recipient can decrypt the message using their private key and the
	// sender's public key. When you decrypt, you must use the same nonce you
	// used to encrypt the message. One way to achieve this is to store the

	// nonce alongside the encrypted message. Above, we stored the nonce in the
	// first 24 bytes of the encrypted text.
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, pkalice, skbob)
	if !ok {
		return errors.New("Error Decrypting Message")
	}
	fmt.Println("Bob Read Message[", string(decrypted), "]")
	return nil
}

func NACLFast(message string) error {
	pkalice, skalice, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return err
	}
	pkbob, skbob, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return err
	}
	fmt.Printf("Original Text: %s\n", message)
	fmt.Println("====NACL Box SealAfterPrecomputation/ OpenAfterPrecomputation====")
	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(crypto_rand.Reader, nonce[:]); err != nil {
		return err
	}
	// shared key used to speed up processing when using the same pair of keys repeatedly.
	sharedEncryptKey := new([32]byte)
	box.Precompute(sharedEncryptKey, pkbob, skalice)
	fmt.Printf("Shared Key [%x\n", *sharedEncryptKey, "]")
	// This encrypts msg and appends the result to the nonce.
	encrypted := box.SealAfterPrecomputation(nonce[:], []byte(message), &nonce, sharedEncryptKey)
	fmt.Printf("Alice Send Encrypted Message to Bob %x\n", &encrypted)
	// The shared key can be used to speed up processing when using the same pair of keys repeatedly.
	var sharedDecryptKey [32]byte
	box.Precompute(&sharedDecryptKey, pkalice, skbob)
	// The recipient can decrypt the message using their private key and the
	// sender's public key. When you decrypt, you must use the same nonce you
	// used to encrypt the message. One way to achieve this is to store the
	// nonce alongside the encrypted message. Above, we stored the nonce in the
	// first 24 bytes of the encrypted text.

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.OpenAfterPrecomputation(nil, encrypted[24:], &decryptNonce, &sharedDecryptKey)
	if !ok {
		return errors.New("decryption error")
	}
	fmt.Println("Bob Read Message[", string(decrypted), "]")
	return nil
}

func NACLSecretBox(message string) error {
	// Do not Use this Key, This is for Demo Purpose only
	var secretKey [32]byte
	copy(secretKey[:], key)
	fmt.Printf("Original Text: %s\n", message)
	fmt.Println("====NACL secretbox Seal/ Open====")
	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}
	encrypted := secretbox.Seal(nonce[:], []byte(message), &nonce, &secretKey)
	fmt.Printf("Encrypted Message: %x\n", encrypted)
	// When you decrypt, you must use the same nonce and key you used to
	// encrypt the message. One way to achieve this is to store the nonce
	// alongside the encrypted message. Above, we stored the nonce in the first
	// 24 bytes of the encrypted text.

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])

	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &secretKey)
	if !ok {
		return errors.New("decryption error")
	}
	fmt.Println(string(decrypted))
	return nil
}

func NACLAuth(message string) {
	// Do not Use this Key, This is for Demo Purpose only

	var secretKey [32]byte
	copy(secretKey[:], key)
	fmt.Printf("Original Text: %s\n", message)
	fmt.Println("====NACL Message Authentication====")
	mac := auth.Sum([]byte(message), &secretKey)
	fmt.Printf("MAC %x\n", *mac)
	result := auth.Verify(mac[:], []byte(message), &secretKey)
	fmt.Println("Verified : ", result)
	badResult := auth.Verify(mac[:], []byte("different message"), &secretKey)
	fmt.Println("Verified : ", badResult)
}

func NACLSign(message string) {
	// Do not Use this Key, This is for Demo Purpose only
	var secretKey [64]byte
	copy(secretKey[:], key)
	fmt.Printf("Original Text: %s\n", message)
	fmt.Println("====NACL Sign/Verify====")
	signature := secretKey[:32]
	signed := secretKey[32:]
	copy(signed, []byte(message))
	fmt.Printf("Signature %x\n", signature)
	result := secretKey[:32]
	copy(result, signed)
	fmt.Println("Verified : ", result)
}
