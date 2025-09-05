// Package main demonstrates how to use the bip39 and hdwallet packages.
package main

import (
	"fmt"
	"log"

	"github.com/kslamph/bip39-hdwallet/bip39"
	"github.com/kslamph/bip39-hdwallet/hdwallet"
)

func main() {
	// Generate a random 128-bit entropy
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Entropy: %x\n", entropy)

	// Generate a mnemonic from the entropy
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Mnemonic: %s\n", mnemonic)

	// Validate the mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		log.Fatal("Invalid mnemonic")
	}
	fmt.Println("Mnemonic is valid")

	// Generate a seed from the mnemonic
	seed := bip39.NewSeed(mnemonic, "TREZOR")
	fmt.Printf("Seed: %x\n", seed)

	// Create a master key from the seed
	masterKey, err := hdwallet.NewMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Master key: %s\n", masterKey)

	// Derive a child key
	childKey, err := masterKey.Derive(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Child key (m/0): %s\n", childKey)

	// Derive a key using a path
	accountKey, err := masterKey.DerivePath("m/44'/0'/0'/0/0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Account key (m/44'/0'/0'/0/0): %s\n", accountKey)
}
