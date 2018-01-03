// Crypt.go is a file encryption/decryption utility that uses AES-GCM to
// encrypt a file. The AES key is derived from a user provided passphrase using
// Argon2.
//
// Usage of crypt:
//   -a string
//     	Action to perform. (default "encrypt")
//   -i string
//     	Input file.
//   -o string
//     	Output file.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
    "io/ioutil"
	"os"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/argon2"
)

// Minimum password length.
const passLen = 16

// Static salt used to seed the Argon2 KDF. Generated with:
// head -c 32 /dev/urandom | base64
const salt = "AKatmtgdkMKq5SFYLt8tBlUxuwLccdCjFfFNi2b3o9A"


// The Cryptor struct manages the encryption and decryption of data.
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

// Create a new Cryptor struct.
// Both the encryption key and the nonce are derived from the passphrase.
func NewCryptor(passphrase string) (*Cryptor, error) {
	c := new(Cryptor)

	kdf := argon2.Key([]byte(passphrase), []byte(salt), 4, 32*1024, 4, 44)
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

// Get the encryption password from the user.
// Ask the user to enter the password twice and verify the passwords match.
// Also verify the password has at least passLen characters.
func getEncPass() string {
	pass1 := getPass("Enter password: ")
	pass2 := getPass("Enter password again: ")

	if pass1 != pass2 {
		fmt.Println("Passwords do not match.")
		os.Exit(0)
	}

	if len(pass1) < passLen {
		fmt.Printf("Password must be at least %d characters.\n", passLen)
		os.Exit(0)
	}

	return pass1
}

// Use x/crypto/ssh/terminal to get the user password without echoing to the
// screen.
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

func main() {
	var action string
	var inFile string
	var outFile string
	var password string
	var inData []byte
	var outData []byte

	flag.StringVar(&action, "a", "encrypt", "Action to perform.")
	flag.StringVar(&inFile, "i", "", "Input file.")
	flag.StringVar(&outFile, "o", "", "Output file.")

	flag.Parse()

	switch action {
	case "encrypt":
		password = getEncPass()
	case "decrypt":
		password = getPass("Enter password: ")
	default:
		flag.Usage()
	}

	cryptor, err := NewCryptor(password)
	check(err)

	inData, err = ioutil.ReadFile(inFile)
	check(err)

	switch action {
	case "encrypt":
		outData = cryptor.Encrypt(inData)
		save(outFile, outData)
	case "decrypt":
		outData, err := cryptor.Decrypt(inData)
		check(err)

		save(outFile, outData)
	}
}
