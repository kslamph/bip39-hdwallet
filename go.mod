module github.com/kslamph/bip39-hdwallet

go 1.25.0

require golang.org/x/crypto v0.41.0

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil v1.1.6
)

require github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
