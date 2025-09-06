// Package main demonstrates how to use the bip39 and hdwallet packages.
package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
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
	masterPrivKey, err := masterKey.PrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Master key (BIP32 root key):\nPrivate key : %x\n", masterPrivKey)
	fmt.Printf("Base58 xprv: %s\n", masterKey.B58Serialize(false))
	fmt.Printf("Base58 xpub: %s\n", masterKey.B58Serialize(true))
	fmt.Println()
	// Derive a BIP32 child key
	BIP32childKey, err := masterKey.Derive(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BIP32 Child key (m/0): %s\n", BIP32childKey)
	fmt.Printf("BIP32 Child key (m/0) (Base58 xprv): %s\n", BIP32childKey.B58Serialize(false))
	fmt.Printf("BIP32 Child key (m/0) (Base58 xpub): %s\n", BIP32childKey.B58Serialize(true))
	fmt.Println()
	// Derive a key using a path(BIP44)
	BIP44accountKeyBTC, err := masterKey.DerivePath("m/44'/0'/0'/0/0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Account key (m/44'/0'/0'/0/0): %s\n", BIP44accountKeyBTC)
	fmt.Printf("Account key (m/44'/0'/0'/0/0) (Base58 xprv): %s\n", BIP44accountKeyBTC.B58Serialize(false))
	fmt.Printf("Account key (m/44'/0'/0'/0/0) (Base58 xpub): %s\n", BIP44accountKeyBTC.B58Serialize(true))

	fmt.Println()
	// Derive a key using a path(BIP49)
	ethAccountKey, err := masterKey.DerivePath("m/44'/60'/0'/0/0")
	if err != nil {
		log.Fatal(err)
	}

	// Convert the private key to an ECDSA private key for Ethereum address generation
	ecdsaPrivKey, err := ethAccountKey.ToECDSA()
	if err != nil {
		log.Fatal(err)
	}

	// Extract the Ethereum address from the ECDSA public key
	publicKey := ecdsaPrivKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Printf("Account key (m/44'/60'/0'/0/0): %s\n", ethAccountKey)
	fmt.Printf("Ethereum address: %s\n", address.Hex())
	fmt.Printf("Ethereum private key: %x\n", ecdsaPrivKey.D.Bytes())
}
