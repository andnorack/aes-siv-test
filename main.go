package main

import (
	"cryptography_tests/gen"
	"encoding/hex"
	"fmt"

	"github.com/google/tink/go/daead/subtle"
)

func Encrypt(key string, pt string) {
	key1, _ := hex.DecodeString(key)
	plaintext := []byte(pt)

	aessiv, err := subtle.NewAESSIV(key1)
	if err != nil {
		panic(err)
	}
	nonce := []byte(gen.RandRunes(12))
	ct, err := aessiv.EncryptDeterministically(plaintext, nonce)
	if err != nil {
		panic(err)
	}

	nonce1 := hex.EncodeToString(nonce)

	fmt.Printf("%x:%s\n", ct, nonce1)
}

func Decrypt(key string, nonce string, ct string) {
	key1, _ := hex.DecodeString(key)
	nonce1, _ := hex.DecodeString(nonce)
	ciphertext, _ := hex.DecodeString(ct)

	aessiv, err := subtle.NewAESSIV(key1)
	if err != nil {
		panic(err)
	}

	pt, err := aessiv.DecryptDeterministically(ciphertext, nonce1)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", pt)
}

func main() {
	key := "35585392382589247847345587355386635944962298992675387735448856497782976975874839357828342925554322327795272463376866679679924335"
	nonce := "566d4e397671385848423931"
	plaintext := "1"

	ciphertext := "4d327ce3d5703d1dce03770c3278c62192"

	Encrypt(key, plaintext)
	Decrypt(key, nonce, ciphertext)
}
