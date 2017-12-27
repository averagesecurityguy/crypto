Crypto
======
Some basic crypto utilities.

* `spud` is a C program to encrypt and decrypt a file with a passphrase. Uses [libsodium](http://doc.libsodium.org/index.html).
* `crypt.go` is a Go program to encrypt and decrypt a file with a passphrase. Uses AES-GCM and Argon2. DO NOT USE: Argon2 is Broken. https://github.com/golang/go/issues/23245
