package main

import (
    "bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
    "strings"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/argon2"
)


type Cryptor struct {
	Aead *cipher.AEAD
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
	kdf := argon2.Key([]byte(passphrase), salt, 4, 32*1024, 4, 56)

	c.Nonce = kdf[32:]

	block, err := aes.NewCipher(kdf[:32])
	if err != nil {
		c, err
	}

	c.Aead, err := cipher.NewGCM(block)
	if err != nil {
		c, err
	}

	return c, nil
}


func getPass(prompt string) string {
    fmt.Print(prompt)
    pass, err := terminal.ReadPassword(int(syscall.Stdin))
    if err != nil {
		os.Exit("Could not read password.")
	}

	pass = strings.TrimSpace(pass)

	if len(pass) < 16 {
		os.Exit("Password must be at least 16 characters.")
	}

	return pass
}

func save(name string, data []byte) {
	err := ioutil.WriteFile(name, data, 0644)
	check(err)
}

func usage() {
	fmt.Println("Usage: crypt command infile outfile")
	fmt.Println("\tcommand must be either encrypt or decrypt.")
	os.Exit(0)
}


func main() {
	if len(os.Args) != 3 {
		usage()
	}

	// Parse arguments
	action := os.Args[0]
	iFile := os.Args[1]
	oFile := os.Args[2]

	// Get Password
	pass1 = getPass("Enter password: ")
	pass2 = getPass("Enter password again: ")

	// Compare passwords.
	if pass1 != pass2 {
		os.Exit("Passwords do not match.")
	}

    var iData []byte
	var oData []byte

	cryptor := NewCryptor(pass1)
	iData, err := ioutil.ReadFile(iFile)
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
