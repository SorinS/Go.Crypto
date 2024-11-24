package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	pk, err := RSA(2048)
	if err != nil {
		fmt.Printf("error RSA 2048: %v\n", err.Error)
		os.Exit(1)
	}
	fmt.Println("RSA 2048 Private Key ", *pk)
	fmt.Println("RSA 2048 Public Key ", pk.PublicKey)

	secretMessage := "Hello 8gwifi.org"
	encryptedMessage, err := EncryptOAEP(secretMessage, pk.PublicKey)
	if err != nil {
		fmt.Println("Error encrypting: ", err)
		os.Exit(2)
	}
	fmt.Println("Cipher Text ", encryptedMessage)
	fmt.Println("Decrytped Text ", DecryptOAEP(encryptedMessage, *pk))
	fmt.Println("Original Text ", secretMessage)
	signature, err := SignPKCS1v15(secretMessage, *pk)
	if err != nil {
		fmt.Println("Error signing: ", err)
		os.Exit(3)
	}
	fmt.Println("Singature : ", signature)
	if err := VerifyPKCS1v15(signature, secretMessage, pk.PublicKey); err != nil {
		fmt.Println("Error verifying: ", err)
		os.Exit(3)
	}
	fmt.Println("Signature Verified")

	// PSS Signature
	pssSignature, err := SignPSS(secretMessage, *pk)
	if err != nil {
		fmt.Printf("Error signing: %v\n", err)
		os.Exit(4)
	}
	fmt.Println("PSS Signature : ", pssSignature)
	err = VerifyPSS(pssSignature, secretMessage, pk.PublicKey)
	if err != nil {
		fmt.Println("Error verifying PSS signature: ", err)
		os.Exit(5)
	}
	fmt.Println("PSS Signature Verified")
}

func RSA(size int) (*rsa.PrivateKey, error) {
	// Generate Alice RSA keys Of 2048 Buts
	return rsa.GenerateKey(rand.Reader, size)
}

func EncryptOAEP(secretMessage string, pubkey rsa.PublicKey) (string, error) {
	label := []byte("OAEP Encrypted")
	// crypto/rand.Reader is a good source of entropy for randomizing the encryption function.
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &pubkey, []byte(secretMessage), label)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptOAEP(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	// crypto/rand.Reader is a good source of entropy for blinding the RSA operation.
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return "Error from Decryption"
	}
	fmt.Printf("Plaintext: %s\n", string(plaintext))
	return string(plaintext)
}

func SignPKCS1v15(plaintext string, privKey rsa.PrivateKey) (string, error) {
	// crypto/rand.Reader is a good source of entropy for blinding the RSA operation.
	rng := rand.Reader
	hashed := sha256.Sum256([]byte(plaintext))
	signature, err := rsa.SignPKCS1v15(rng, &privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func VerifyPKCS1v15(signature string, plaintext string, pubkey rsa.PublicKey) error {
	sig, _ := base64.StdEncoding.DecodeString(signature)
	hashed := sha256.Sum256([]byte(plaintext))
	return rsa.VerifyPKCS1v15(&pubkey, crypto.SHA256, hashed[:], sig)
}

func SignPSS(plaintext string, privKey rsa.PrivateKey) (string, error) {
	// crypto/rand.Reader is a good source of entropy for blinding the RSA operation.
	rng := rand.Reader
	hashed := sha256.Sum256([]byte(plaintext))
	var opts rsa.PSSOptions
	signature, err := rsa.SignPSS(rng, &privKey, crypto.SHA256, hashed[:], &opts)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func VerifyPSS(signature string, plaintext string, pubkey rsa.PublicKey) error {
	sig, _ := base64.StdEncoding.DecodeString(signature)
	hashed := sha256.Sum256([]byte(plaintext))
	var opts rsa.PSSOptions
	return rsa.VerifyPSS(&pubkey, crypto.SHA256, hashed[:], sig, &opts)
}

func SavePKCS8RSAPEMKey(fName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fName)
	if err != nil {
		return err
	}
	defer outFile.Close()
	//converts a private key to ASN.1 DER encoded form.
	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.Encode(outFile, privateKey)
}

func SavePKCS1RSAPublicPEMKey(fName string, pubkey *rsa.PublicKey) error {
	//converts an RSA public key to PKCS#1, ASN.1 DER form.
	var pemkey = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubkey),
	}
	pemfile, err := os.Create(fName)
	if err != nil {
		return err
	}
	defer pemfile.Close()
	return pem.Encode(pemfile, pemkey)
}

func SavePublicPEMKey(fileName string, pubkey rsa.PublicKey) error {
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return err
	}
	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	pemfile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer pemfile.Close()
	return pem.Encode(pemfile, pemkey)
}

func LoadRSAPrivatePemKey(fileName string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	if err != nil {
		return nil, err
	}
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()
	return x509.ParsePKCS1PrivateKey(data.Bytes)
}

func LoadPublicPemKey(fileName string) (*rsa.PublicKey, error) {
	publicKeyFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	pemfileinfo, _ := publicKeyFile.Stat()
	size := pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	publicKeyFile.Close()
	return x509.ParsePKCS1PublicKey(data.Bytes)
}
