// Package main demonstrates how to use the bip39 and hdwallet packages.
package main

import (
	"fmt"
	"log"

	"github.com/kslamph/bip39-hdwallet/bip39"
	"github.com/kslamph/bip39-hdwallet/hdwallet"
)

func main() {
	// Generate a random 256-bit entropy
	entropy, err := bip39.NewEntropy(256)
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
	fmt.Printf("BIP39 Seed: %x\n", seed)
	fmt.Println()

	// Create a master key from the seed
	masterKey, err := hdwallet.NewMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Master key (BIP32 root key):\nPrivate key : %x\n", masterKey.Key)
	fmt.Printf("Base58 xprv: %s\n", masterKey.B58Serialize(false))
	fmt.Printf("Base58 xpub: %s\n", masterKey.B58Serialize(true))
	fmt.Println()
	// Derive a BIP32 child key
	childKey, err := masterKey.Derive(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BIP32 Child key (m/0): %s\n", childKey)
	fmt.Printf("BIP32 Child key (m/0) (Base58 xprv): %s\n", childKey.B58Serialize(false))
	fmt.Printf("BIP32 Child key (m/0) (Base58 xpub): %s\n", childKey.B58Serialize(true))
	fmt.Println()
	// Derive a key using a path(BIP44)
	accountKey, err := masterKey.DerivePath("m/44'/0'/0'/0/0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Account key (m/44'/0'/0'/0/0): %s\n", accountKey)
	fmt.Printf("Account key (m/44'/0'/0'/0/0) (Base58 xprv): %s\n", accountKey.B58Serialize(false))
	fmt.Printf("Account key (m/44'/0'/0'/0/0) (Base58 xpub): %s\n", accountKey.B58Serialize(true))
}
