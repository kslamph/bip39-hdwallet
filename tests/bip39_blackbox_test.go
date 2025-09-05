package tests

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/kslamph/bip39-hdwallet/bip39"
)

// BIP39Test represents a single test case from the BIP39 test vectors.
type BIP39Test struct {
	Entropy  string `json:"entropy"`
	Mnemonic string `json:"mnemonic"`
	Seed     string `json:"seed"`
	XPRV     string `json:"xprv"`
}

// unmarshalBIP39TestVectors reads and unmarshals the BIP39 test vectors from a JSON file.
func unmarshalBIP39TestVectors(t *testing.T, filename string) map[string][]BIP39Test {
	filepath := filepath.Join("..", "ref", filename)
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read test vectors file %s: %v", filename, err)
	}

	var rawData map[string][][]string
	if err := json.Unmarshal(data, &rawData); err != nil {
		t.Fatalf("Failed to unmarshal test vectors from %s: %v", filename, err)
	}

	testVectors := make(map[string][]BIP39Test)
	for lang, vectors := range rawData {
		var tests []BIP39Test
		for _, v := range vectors {
			if len(v) != 4 {
				t.Fatalf("Unexpected number of fields in test vector for %s: %v", lang, v)
			}
			tests = append(tests, BIP39Test{
				Entropy:  v[0],
				Mnemonic: v[1],
				Seed:     v[2],
				XPRV:     v[3],
			})
		}
		testVectors[lang] = tests
	}
	return testVectors
}

func TestBIP39BlackboxVectors(t *testing.T) {
	testVectors := unmarshalBIP39TestVectors(t, "vip39-vectors.json")

	// Iterate over all languages
	for lang, tests := range testVectors {
		t.Run(lang, func(t *testing.T) {
			for i, tc := range tests {
				t.Run(string(i), func(t *testing.T) {
					entropyBytes, err := hex.DecodeString(tc.Entropy)
					if err != nil {
						t.Fatalf("Failed to decode entropy hex: %v", err)
					}

					// Test NewMnemonic
					mnemonic, err := bip39.NewMnemonic(entropyBytes)
					if err != nil {
						t.Errorf("NewMnemonic(%s) error: %v", tc.Entropy, err)
					}
					if mnemonic != tc.Mnemonic {
						t.Errorf("NewMnemonic(%s) = %s; want %s", tc.Entropy, mnemonic, tc.Mnemonic)
					}

					// Test MnemonicToByteArray
					decodedEntropy, err := bip39.MnemonicToByteArray(tc.Mnemonic)
					if err != nil {
						t.Errorf("MnemonicToByteArray(%s) error: %v", tc.Mnemonic, err)
					}
					if !bytes.Equal(decodedEntropy, entropyBytes) {
						t.Errorf("MnemonicToByteArray(%s) = %x; want %s", tc.Mnemonic, decodedEntropy, tc.Entropy)
					}

					// Test NewSeed with empty passphrase (as per BIP39 test vectors imply)
					seed := bip39.NewSeed(tc.Mnemonic, "TREZOR")
					expectedSeed, err := hex.DecodeString(tc.Seed)
					if err != nil {
						t.Fatalf("Failed to decode expected seed hex: %v", err)
					}
					if !bytes.Equal(seed, expectedSeed) {
						t.Errorf("NewSeed(%s, \"TREZOR\") = %x; want %x", tc.Mnemonic, seed, expectedSeed)
					}

					// Test IsMnemonicValid
					if !bip39.IsMnemonicValid(tc.Mnemonic) {
						t.Errorf("IsMnemonicValid(%s) = false; want true", tc.Mnemonic)
					}
				})
			}
		})
	}

	// Test invalid mnemonic for MnemonicToByteArray
	_, err := bip39.MnemonicToByteArray("invalid invalid invalid")
	if err == nil {
		t.Error("MnemonicToByteArray(invalid mnemonic) = nil; want error")
	}

	// Test invalid mnemonic for IsMnemonicValid
	invalidMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid"
	if bip39.IsMnemonicValid(invalidMnemonic) {
		t.Errorf("IsMnemonicValid(%s) = true; want false", invalidMnemonic)
	}
}