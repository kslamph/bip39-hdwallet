# BIP39 and HD Wallet Implementation

This repository contains Go implementations of BIP39 (mnemonic codes) and BIP32/BIP44 (hierarchical deterministic wallets).

## Packages

### bip39

Implements the BIP39 specification for mnemonic codes.

```go
import "github.com/yourusername/bip39-hdwallet/bip39"
```

#### Features

- Generate random entropy for mnemonic creation
- Convert entropy to mnemonic phrases
- Validate mnemonic phrases
- Convert mnemonic phrases back to entropy
- Generate seeds from mnemonics with optional passphrases

#### Example Usage

```go
// Generate a random 128-bit entropy
entropy, err := bip39.NewEntropy(128)
if err != nil {
    log.Fatal(err)
}

// Generate a mnemonic from the entropy
mnemonic, err := bip39.NewMnemonic(entropy)
if err != nil {
    log.Fatal(err)
}

// Validate the mnemonic
if !bip39.IsMnemonicValid(mnemonic) {
    log.Fatal("Invalid mnemonic")
}

// Generate a seed from the mnemonic
seed := bip39.NewSeed(mnemonic, "TREZOR")
```

### hdwallet

Implements the BIP32 and BIP44 specifications for hierarchical deterministic wallets.

```go
import "github.com/kslamph/bip39-hdwallet/hdwallet"
```

#### Features

- Create master keys from seeds
- Derive child keys (normal and hardened)
- Derive keys using derivation paths
- Support for BIP44 standard paths

#### Example Usage

```go
// Create a master key from the seed
masterKey, err := hdwallet.NewMasterKey(seed)
if err != nil {
    log.Fatal(err)
}

// Derive a child key
childKey, err := masterKey.Derive(0)
if err != nil {
    log.Fatal(err)
}

// Derive a key using a path
accountKey, err := masterKey.DerivePath("m/44'/0'/0'/0/0")
if err != nil {
    log.Fatal(err)
}
```

## Installation

```bash
go get github.com/kslamph/bip39-hdwallet
```

## Security

This implementation follows the BIP39, BIP32, and BIP44 specifications exactly. It uses cryptographic secure random number generation and industry standard hashing algorithms.

## Testing

Run tests with:

```bash
go test ./...
```

## License

MIT