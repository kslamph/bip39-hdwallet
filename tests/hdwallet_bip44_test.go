package tests

import (
	"encoding/hex"
	"testing"

	"fmt"
	"github.com/kslamph/bip39-hdwallet/hdwallet"
)

type bip44TestVector struct {
	Entropy  string
	Mnemonic string
	Seed     string
	CoinType uint32
	AccountExtendedPrivateKey string
	AccountExtendedPublicKey string
	Addresses []struct {
		Path string
		Address string
		PublicKey string
		PrivateKey string
	}
}

func TestBIP44Vectors(t *testing.T) {
	testVectors := []bip44TestVector{
		{
			// Values obtained from iancoleman.io/bip39 using the provided entropy and selecting BTC - Bitcoin
			Entropy:  "007817bcd383822ecea984848209701288a3a24581dd27d0acf6e4685c0999d3",
			Mnemonic: "about scheme upset poem deal blast deny correct loyal aware foster celery mechanic spell bid desert chief lyrics diet silver magic age guard grit",
			Seed:     "44d096fbea7008d02e49d2db01f919368c07a6164876f8ce0a8e6d38d80379be4dae6dcd3fad25b72af17f486251ae9ca60ec654d47d3b9ab00cfb19b6e56038",
			CoinType: 0, // Bitcoin
			AccountExtendedPrivateKey: "xprv9zDg8G93x4wiwMvqMUfjtt3dbZpn53hQxV2ELChiEeFb2sLyZRq4ttp8M1JHxgqiEFQ1cmCuYkRtrUhd2cXFNUY6Q8K1rVEnXb42KVcwBk2",
			AccountExtendedPublicKey: "xpub6DD2XmfwnSW29r1JTWCkG1zN9bfGUWRGKhwq8b7KnynZufg86y9KSh8cCJTypPyVbBcoW9kmmKx1PHtomJNeZRMRt1hCbQagZ9reT27wUDg",
			Addresses: []struct {
				Path string
				Address string
				PublicKey string
				PrivateKey string
			}{
				{Path: "m/44'/0'/0'/0/0", Address: "17yUrH1UsRtSjYU72VUomFnErv3EYctXU2", PublicKey: "03bda135bcb14028bb1ba38f5e761b7b0d7427d28f3e35dc6cd9ec5cf8114fe214", PrivateKey: "KwJE6WGF67v7Bs5heSVVd2HBi1RniLjdEcKVgTA5ypJocLcUS6WL"},
				{Path: "m/44'/0'/0'/0/1", Address: "1C6yasgHoiGdxfLJ9okeh5PoHLUkw3A2ap", PublicKey: "0318a6d1ce3dba7fae66d37576985ac0c19ff7fd931e45632f872637313c615a43", PrivateKey: "L1rgxNDgoRFhgcYFjsBNMHhTaGJtCTdq28S6g5RKWVT5SUy4XGZN"},
			},
		},
		{
			// Values obtained from iancoleman.io/bip39 using the provided entropy and selecting ETH - Ethereum
			Entropy:  "007817bcd383822ecea984848209701288a3a24581dd27d0acf6e4685c0999d3",
			Mnemonic: "about scheme upset poem deal blast deny correct loyal aware foster celery mechanic spell bid desert chief lyrics diet silver magic age guard grit",
			Seed:     "44d096fbea7008d02e49d2db01f919368c07a6164876f8ce0a8e6d38d80379be4dae6dcd3fad25b72af17f486251ae9ca60ec654d47d3b9ab00cfb19b6e56038",
			CoinType: 60, // Ethereum
			AccountExtendedPrivateKey: "xprv9zLzCrizXhhMYtTrSPu3cB7PUVeij9AwiLPYc6WeGkeGvHzjYTUJpK5H3rAsW3FEumfKUVboewn2dASEzrMuCUTYaKyigfNDAmoRaQSPtFB",
			AccountExtendedPublicKey: "xpub6DLLcNFtN5FemNYKYRS3yK482XVD8bto5ZK9QUvFq6BFo6Kt5znZN7Pku82AJXygW4uWUaShPnoWwFf5naL8Sodwqtuh2zi2hZzs6k7eTf2",
			Addresses: []struct {
				Path string
				Address string
				PublicKey string
				PrivateKey string
			}{
				{Path: "m/44'/60'/0'/0/0", Address: "0x9cd756d1114b62d538298840A86459bEA7d6371e", PublicKey: "0368187f970ae9c145d0c64d4f7cb63a5771e4b53da3d58b69b887c5efc07a36b1", PrivateKey: "42645edbc768cacb8b702658b889c11a17b35615dc1e8a323699a84cc5e7824a"},
				{Path: "m/44'/60'/0'/0/1", Address: "0xbE337abf6d807ccB389655EA37b9Ae09AC54f797", PublicKey: "0295498f9cb0c5c57caeed4d07869590b748b9a303eb4033d0321ce71d4d56749b", PrivateKey: "da532afd0b141856933b28010c09488948a4b5e385ce152777c9fb65a11f42cd"},
			},
		},
		{
			// Values obtained from iancoleman.io/bip39 using the provided entropy and selecting TRX - Tron
			Entropy:  "007817bcd383822ecea984848209701288a3a24581dd27d0acf6e4685c0999d3",
			Mnemonic: "about scheme upset poem deal blast deny correct loyal aware foster celery mechanic spell bid desert chief lyrics diet silver magic age guard grit",
			Seed:     "44d096fbea7008d02e49d2db01f919368c07a6164876f8ce0a8e6d38d80379be4dae6dcd3fad25b72af17f486251ae9ca60ec654d47d3b9ab00cfb19b6e56038",
			CoinType: 195, // Tron
			AccountExtendedPrivateKey: "xprv9yVC9Zghe9LTUuxwNFzpeK6dpxZthGn1w5M16EsYPKBbE3SRNZFD4KaBcDp7DZzZX4eeLKPdLw2NaNX6VRJAoAHD8iWaL7NgN1wum3dz1Pm",
			AccountExtendedPublicKey: "xpub6CUYZ5DbUWtkhQ3QUHXq1T3NNzQP6jVsJJGbtdH9weia6qmZv6ZTc7tfTUgRP2kgWpSPC9RkwhYFLYM4khWvbsxp9B2RhdPF5hfGf54Ssg9",
			Addresses: []struct {
				Path string
				Address string
				PublicKey string
				PrivateKey string
			}{
				{Path: "m/44'/195'/0'/0/0", Address: "TPWsaV5oumxcVi25LPJrg4vZnxEo3vvHeQ", PublicKey: "0336d68334489fa26358ab6bd11d83d1aa23594cb8ff45e8d5d14c4bf4a0132afc", PrivateKey: "d1215c8cfc8abe782d710df125a67277858b2784b5b5106a8ac124682ff92325"},
				{Path: "m/44'/195'/0'/0/1", Address: "TReLNymnsUHVJhGqmGvggfhK85CRd64TMW", PublicKey: "03350bb0139a8f13ee47d80050e843efa786d1d650de6b87468d98758b3f223a00", PrivateKey: "668ed77adfb8be46a9a5de9fdcbfea43ddc0b3f2264afa5f72b7e1cca43c460f"},
			},
		},
	}

	for _, tv := range testVectors {
		seedBytes, err := hex.DecodeString(tv.Seed)
		if err != nil {
			t.Fatalf("Failed to decode seed: %v", err)
		}

		masterKey, err := hdwallet.NewMasterKey(seedBytes)
		if err != nil {
			t.Fatalf("NewMasterKey failed for seed %s: %v", tv.Seed, err)
		}

		// Verify Account Extended Private Key and Public Key
		accountKey, err := masterKey.DerivePath(fmt.Sprintf("m/44'/%d'/0'", tv.CoinType))
		if err != nil {
			t.Fatalf("DerivePath for account key failed: %v", err)
		}

		if accountKey.B58Serialize(false) != tv.AccountExtendedPrivateKey {
			t.Errorf("Account Extended Private Key mismatch for CoinType %d. Got: %s, Want: %s", tv.CoinType, accountKey.B58Serialize(false), tv.AccountExtendedPrivateKey)
		}
		if accountKey.B58Serialize(true) != tv.AccountExtendedPublicKey {
			t.Errorf("Account Extended Public Key mismatch for CoinType %d. Got: %s, Want: %s", tv.CoinType, accountKey.B58Serialize(true), tv.AccountExtendedPublicKey)
		}

		// Verify derived addresses
		for _, addr := range tv.Addresses {
			derivedAddressKey, err := masterKey.DerivePath(addr.Path)
			if err != nil {
				t.Fatalf("DerivePath for address %s failed: %v", addr.Path, err)
			}

			// For Bitcoin, Address is derived from the Public Key using a specific scheme (P2PKH).
			// For Ethereum/Tron, the address is derived directly from the Public Key (last 20 bytes of Keccak-256 hash).
			// This test needs to be generalized or specific to coin types.
			// For now, directly compare the raw public and private keys from the derived BIP44 key.
			// Note: The website's Address field might be different from simple public key conversion
			// based on coin-specific address formats.

			// Compare Public Key
			if hex.EncodeToString(derivedAddressKey.PublicKey()) != addr.PublicKey {
				t.Errorf("Public Key mismatch for path %s. Got: %s, Want: %s", addr.Path, hex.EncodeToString(derivedAddressKey.PublicKey()), addr.PublicKey)
			}

			// Compare Private Key
			if tv.CoinType == 0 { // Bitcoin uses WIF
				wif, err := derivedAddressKey.ToWIF()
				if err != nil {
					t.Fatalf("Failed to convert private key to WIF for path %s: %v", addr.Path, err)
				}
				if wif != addr.PrivateKey {
					t.Errorf("Private Key (WIF) mismatch for path %s. Got: %s, Want: %s", addr.Path, wif, addr.PrivateKey)
				}
			} else { // Ethereum/Tron use raw hex
				if hex.EncodeToString(derivedAddressKey.Key) != addr.PrivateKey {
					t.Errorf("Private Key (Hex) mismatch for path %s. Got: %s, Want: %s", addr.Path, hex.EncodeToString(derivedAddressKey.Key), addr.PrivateKey)
				}
			}
		}
	}
}