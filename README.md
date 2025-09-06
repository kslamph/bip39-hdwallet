# BIP39 and HD Wallet Implementation

[![GoDoc](https://godoc.org/github.com/kslamph/bip39-hdwallet?status.svg)](https://godoc.org/github.com/kslamph/bip39-hdwallet)
[![Go Report Card](https://goreportcard.com/badge/github.com/kslamph/bip39-hdwallet)](https://goreportcard.com/report/github.com/kslamph/bip39-hdwallet)
[![codecov](https://codecov.io/gh/kslamph/bip39-hdwallet/branch/main/graph/badge.svg)](https://codecov.io/gh/kslamph/bip39-hdwallet)

This repository contains Go implementations of BIP39 (mnemonic codes) and BIP32/BIP44 (hierarchical deterministic wallets).

## Migration from Deprecated Packages

This package was created as a direct replacement for popular but now-deleted packages:

- `github.com/tyler-smith/go-bip39` - A widely-used BIP39 implementation that was recently deleted

Many popular packages like `github.com/miguelmota/go-ethereum-hdwallet` are affected.

If you're looking for alternatives to these packages or need to upgrade your dependencies, this repository provides a drop-in replacement with improved features and ongoing maintenance.

This package maintains API compatibility with the deleted packages, including all the same function names:
- `EntropyFromMnemonic()` for converting mnemonics back to entropy
- `MnemonicToByteArray()` with optional raw parameter extension
- `NewSeedWithErrorChecking()` for mnemonic validation before seed generation
- `GetWordList()` and `GetWordIndex()` for wordlist operations

Search terms: go-bip39, go-ethereum-hdwallet, BIP39 migration, HD wallet replacement


## Packages

### bip39

Implements the BIP39 specification for mnemonic codes.

```go
import "github.com/kslamph/bip39-hdwallet/bip39"
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

## High Test Coverage

This package maintains a high test coverage standard (over 85% for both packages) to ensure reliability and correctness of cryptographic operations.

## Testing

Run tests with:

```bash
go test ./...
```

## Coverage Reporting

To generate and view local coverage reports:
```bash
# Generate coverage report
go test -coverprofile=coverage.txt ./...

# View coverage in browser
go tool cover -html=coverage.txt
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.