module example

go 1.25.0

replace github.com/kslamph/bip39-hdwallet => ../.

require (
	github.com/ethereum/go-ethereum v1.16.3
	github.com/kslamph/bip39-hdwallet v0.0.0-00010101000000-000000000000
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.6 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)
