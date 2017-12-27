package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
    "io/ioutil"
	"os"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/argon2"
)


type Cryptor struct {
	Aead cipher.AEAD
	Nonce []byte
}

func (c *Cryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.Aead.Open(nil, c.Nonce, ciphertext, nil)
}

func (c *Cryptor) Encrypt(plaintext []byte) []byte {
	return c.Aead.Seal(nil, c.Nonce, plaintext, nil)
}

func NewCryptor(passphrase string) (*Cryptor, error) {
	c := new(Cryptor)

	// Static salt used to seed Argon2. Generated with:
	// head -c 32 /dev/urandom | base64
	salt := []byte("AKatmtgdkMKq5SFYLt8tBlUxuwLccdCjFfFNi2b3o9A")
	kdf := argon2.Key([]byte(passphrase), salt, 4, 32*1024, 4, 44)

	c.Nonce = kdf[32:]

	block, err := aes.NewCipher(kdf[:32])
	if err != nil {
		return c, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return c, err
	}

    c.Aead = aead

	return c, nil
}


func getPass(prompt string) string {
    fmt.Print(prompt)
    pass, err := terminal.ReadPassword(int(syscall.Stdin))
    if err != nil {
        fmt.Println("\nCould not read password.")
		os.Exit(0)
	}

    fmt.Println("")

	return string(pass)
}

func save(name string, data []byte) {
	err := ioutil.WriteFile(name, data, 0644)
	check(err)
}

func check(e error) {
    if e != nil {
        fmt.Printf("Error: %s\n", e.Error())
        os.Exit(0)
    }
}


func usage() {
	fmt.Println("Usage: crypt command infile outfile")
	fmt.Println("\tcommand must be either encrypt or decrypt.")
	os.Exit(0)
}


func main() {
	if len(os.Args) != 4 {
		usage()
	}

	// Parse arguments
	action := os.Args[1]
	iFile := os.Args[2]
	oFile := os.Args[3]

	// Get Password
	pass1 := getPass("Enter password: ")
	pass2 := getPass("Enter password again: ")

	// Compare passwords.
	if pass1 != pass2 {
		fmt.Println("Passwords do not match.")
        os.Exit(0)
	}

    // Check password length
    if len(pass1) < 16 {
		fmt.Println("Password must be at least 16 characters.")
        os.Exit(0)
	}


    var iData []byte
	var oData []byte

	cryptor, err := NewCryptor(pass1)
    check(err)

	iData, err = ioutil.ReadFile(iFile)
	check(err)

	switch action {
	case "encrypt":
		oData = cryptor.Encrypt(iData)
		save(oFile, oData)
	case "decrypt":
		oData, err := cryptor.Decrypt(iData)
		check(err)

		save(oFile, oData)
	default:
		usage()
	}
}
