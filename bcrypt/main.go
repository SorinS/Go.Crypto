package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	password := "myverystrongpassword-8gwifi.org"
	cost := 10 // Cost Factor

	// Every time this program runs produce a different Hash Value
	b, _ := bcrypt.GenerateFromPassword([]byte(password), cost)
	fmt.Printf("Bcrypt Hash: %s\n", b)

	// This is a valid Bcrypt hash for the given password
	validhashcomp := "$2a$10$Hti8Mqe/UOR8Ss/7RRCGVeDDOWABkemkk13xSOESYKVOO0PWegJBq"

	//CompareHashAndPassword compares a bcrypt hashed password with its possible
	// plaintext equivalent. Returns nil on success, or an error on failure.
	if bcrypt.CompareHashAndPassword([]byte(validhashcomp), []byte(password)) != nil {
		fmt.Printf("Invalid Bcrypt Hash\n")
	} else {
		fmt.Printf("Valid Bcrypt Hash\n")
	}
	// This is an INVALID Bcrypt hash for the given password
	invalidhashcomp := "$2a$10$36dINuo6R.n0aEjW5EOS0O0u0VeQZXBlgqKXqqA62qMu6c65ngB8C"
	if bcrypt.CompareHashAndPassword([]byte(invalidhashcomp), []byte(password)) != nil {
		fmt.Printf("Invalid Bcrypt Hash\n")
	} else {
		fmt.Printf("Valid Bcrypt Hash\n")
	}
}
