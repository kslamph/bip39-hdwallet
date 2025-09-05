package bip39

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNewEntropy(t *testing.T) {
	// Test valid entropy sizes
	for _, size := range []int{128, 160, 192, 224, 256} {
		entropy, err := NewEntropy(size)
		if err != nil {
			t.Errorf("NewEntropy(%d) error: %v", size, err)
		}
		if len(entropy)*8 != size {
			t.Errorf("NewEntropy(%d) = %d bits; want %d bits", size, len(entropy)*8, size)
		}
	}

	// Test invalid entropy sizes
	for _, size := range []int{127, 129, 257, 300} {
		_, err := NewEntropy(size)
		if err != ErrEntropyLength {
			t.Errorf("NewEntropy(%d) = %v; want ErrEntropyLength", size, err)
		}
	}
}

func TestNewMnemonic(t *testing.T) {
	// Test cases from BIP39 spec
	testCases := []struct {
		entropyHex string
		mnemonic   string
	}{
		{
			"00000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		},
		{
			"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"legal winner thank year wave sausage worth useful legal winner thank yellow",
		},
		{
			"80808080808080808080808080808080",
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
		},
		{
			"ffffffffffffffffffffffffffffffff",
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		},
		{
			"000000000000000000000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		},
		{
			"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		},
		{
			"808080808080808080808080808080808080808080808080",
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		},
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffff",
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		},
		{
			"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		},
		{
			"8080808080808080808080808080808080808080808080808080808080808080",
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		},
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		},
	}

	for _, tc := range testCases {
		entropy, err := hex.DecodeString(tc.entropyHex)
		if err != nil {
			t.Errorf("Failed to decode entropy hex: %v", err)
			continue
		}

		mnemonic, err := NewMnemonic(entropy)
		if err != nil {
			t.Errorf("NewMnemonic(%s) error: %v", tc.entropyHex, err)
			continue
		}

		if mnemonic != tc.mnemonic {
			t.Errorf("NewMnemonic(%s) = %s; want %s", tc.entropyHex, mnemonic, tc.mnemonic)
		}
	}
}

func TestMnemonicToByteArray(t *testing.T) {
	// Test cases from BIP39 spec
	testCases := []struct {
		mnemonic   string
		entropyHex string
	}{
		{
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"00000000000000000000000000000000",
		},
		{
			"legal winner thank year wave sausage worth useful legal winner thank yellow",
			"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		},
		{
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
			"80808080808080808080808080808080",
		},
		{
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
			"ffffffffffffffffffffffffffffffff",
		},
	}

	for _, tc := range testCases {
		entropy, err := MnemonicToByteArray(tc.mnemonic)
		if err != nil {
			t.Errorf("MnemonicToByteArray(%s) error: %v", tc.mnemonic, err)
			continue
		}

		expectedEntropy, err := hex.DecodeString(tc.entropyHex)
		if err != nil {
			t.Errorf("Failed to decode expected entropy hex: %v", err)
			continue
		}

		if !bytes.Equal(entropy, expectedEntropy) {
			t.Errorf("MnemonicToByteArray(%s) = %x; want %s", tc.mnemonic, entropy, tc.entropyHex)
		}
	}

	// Test invalid mnemonic
	_, err := MnemonicToByteArray("invalid invalid invalid")
	if err == nil {
		t.Error("MnemonicToByteArray(invalid mnemonic) = nil; want error")
	}
}

func TestNewSeed(t *testing.T) {
	// Test case from BIP39 spec
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "TREZOR"
	expectedSeed, err := hex.DecodeString("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
	if err != nil {
		t.Fatalf("Failed to decode expected seed hex: %v", err)
	}

	seed := NewSeed(mnemonic, passphrase)
	if !bytes.Equal(seed, expectedSeed) {
		t.Errorf("NewSeed() = %x; want %x", seed, expectedSeed)
	}
}

func TestIsMnemonicValid(t *testing.T) {
	validMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if !IsMnemonicValid(validMnemonic) {
		t.Errorf("IsMnemonicValid(%s) = false; want true", validMnemonic)
	}

	invalidMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid"
	if IsMnemonicValid(invalidMnemonic) {
		t.Errorf("IsMnemonicValid(%s) = true; want false", invalidMnemonic)
	}
}