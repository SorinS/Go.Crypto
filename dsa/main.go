package main

import (
	"crypto/dsa"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
)

func main() {
	// Message to Be signed and Verify
	secretMessage := "Hello 8gwifi.org"
	pvtkey, err := DSAKey(secretMessage, dsa.L1024N160)
	if err != nil {
		fmt.Println("Error DSAKey Key Generation", err)
		os.Exit(1)
	}
	fmt.Printf("Private Key :%x \n", pvtkey)
	fmt.Printf("Public Key %x \n", pvtkey.PublicKey)

	signature, s, err := DSASign(secretMessage, pvtkey)
	if err != nil {
		fmt.Println("Error DSA Sign ", err)
		os.Exit(2)
	}

	if err := DSAVerify(secretMessage, signature, s, &pvtkey.PublicKey); err != nil {
		fmt.Println("Error DSA Verify ", err)
		os.Exit(3)
	}
	fmt.Println("Signature Verification Passed ")
}

func DSAKey(msg string, sizes dsa.ParameterSizes) (*dsa.PrivateKey, error) {
	var priv dsa.PrivateKey
	params := &priv.Parameters
	err := dsa.GenerateParameters(params, rand.Reader, sizes)
	if err != nil {
		return nil, err
	}
	err = dsa.GenerateKey(&priv, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &priv, nil
}

func DSASign(msg string, priv *dsa.PrivateKey) (string, *big.Int, error) {
	hashed := md5.Sum([]byte(msg))
	r, s, err := dsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		return "", big.NewInt(int64(0)), err
	}
	return base64.StdEncoding.EncodeToString(r.Bytes()), s, nil
}

func DSAVerify(msg, sign string, s *big.Int, pub *dsa.PublicKey) error {
	hashed := md5.Sum([]byte(msg))
	signature, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	r := new(big.Int).SetBytes(signature)
	if !dsa.Verify(pub, hashed[:], r, s) {
		return errors.New("Signature Verification Failed")
	}
	return nil
}
