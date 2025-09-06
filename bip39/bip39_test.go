package bip39

import (
	"bytes"
	"encoding/hex"
	"strings"
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

// TestGetBits tests the getBits helper function
func TestGetBits(t *testing.T) {
	// Test case 1: Simple bit extraction
	buf := []byte{0b10110101, 0b11001010}

	// Extract 4 bits starting at bit offset 0 (should get 0b1011 = 11)
	result := getBits(buf, 0, 4)
	if result != 11 {
		t.Errorf("getBits(buf, 0, 4) = %d; want 11", result)
	}

	// Extract 4 bits starting at bit offset 4 (should get 0b0101 = 5)
	result = getBits(buf, 4, 4)
	if result != 5 {
		t.Errorf("getBits(buf, 4, 4) = %d; want 5", result)
	}

	// Extract 8 bits starting at bit offset 0 (should get 0b10110101 = 181)
	result = getBits(buf, 0, 8)
	if result != 181 {
		t.Errorf("getBits(buf, 0, 8) = %d; want 181", result)
	}

	// Extract 1 bit starting at bit offset 1 (should get 0b0 = 0)
	result = getBits(buf, 1, 1)
	if result != 0 {
		t.Errorf("getBits(buf, 1, 1) = %d; want 0", result)
	}

	// Extract 1 bit starting at bit offset 2 (should get 0b1 = 1)
	result = getBits(buf, 2, 1)
	if result != 1 {
		t.Errorf("getBits(buf, 2, 1) = %d; want 1", result)
	}

	// Test edge case: reading beyond buffer (should return 0)
	result = getBits(buf, 20, 1)
	if result != 0 {
		t.Errorf("getBits(buf, 20, 1) = %d; want 0", result)
	}
}

// TestIndicesToBytes tests the indicesToBytes helper function
func TestIndicesToBytes(t *testing.T) {
	// Test case 1: Simple conversion
	indices := []int{0, 1, 2}             // 0b00000000000 0b00000000001 0b00000000010
	result := indicesToBytes(indices, 33) // 3 indices * 11 bits = 33 bits

	// Expected: 0b00000000 0b00000000 0b00000000 0b00000010
	// First byte: 0b00000000 = 0
	// Second byte: 0b00000000 = 0
	// Third byte: 0b00000000 = 0
	// Fourth byte: 0b00000010 = 2 (only the last bit from the third index)

	if len(result) != 5 { // (33+7)/8 = 5 bytes
		t.Errorf("indicesToBytes result length = %d; want 5", len(result))
	}

	// Test case 2: More complex conversion
	indices = []int{2047, 1024, 512} // 0b11111111111 0b10000000000 0b01000000000
	result = indicesToBytes(indices, 33)

	// Check that we have the right number of bytes
	if len(result) != 5 {
		t.Errorf("indicesToBytes result length = %d; want 5", len(result))
	}
}

// TestNewMnemonicErrors tests error conditions in NewMnemonic
func TestNewMnemonicErrors(t *testing.T) {
	// Test with invalid entropy lengths (not multiples of 32)
	invalidLengths := []int{120, 136, 152, 168, 184, 200, 216, 232, 248, 264, 300}

	for _, length := range invalidLengths {
		entropy := make([]byte, length/8)
		_, err := NewMnemonic(entropy)
		if err != ErrEntropyLength {
			t.Errorf("NewMnemonic with %d-bit entropy = %v; want ErrEntropyLength", length, err)
		}
	}

	// Test with valid length but zero entropy (edge case)
	entropy := make([]byte, 16) // 128 bits
	mnemonic, err := NewMnemonic(entropy)
	if err != nil {
		t.Errorf("NewMnemonic with zero entropy = %v; want nil error", err)
	}
	if mnemonic == "" {
		t.Error("NewMnemonic with zero entropy returned empty mnemonic")
	}
}

// TestMnemonicToByteArrayErrors tests error conditions in MnemonicToByteArray
func TestMnemonicToByteArrayErrors(t *testing.T) {
	// Test with invalid word counts (not multiples of 3 or outside 12-24 range)
	invalidWordCounts := []int{1, 2, 3, 9, 10, 11, 25, 26, 27}

	for _, count := range invalidWordCounts {
		words := make([]string, count)
		for i := range words {
			words[i] = "abandon" // Use a valid word
		}
		mnemonic := strings.Join(words, " ")

		_, err := MnemonicToByteArray(mnemonic)
		if err != ErrMnemonicLength {
			t.Errorf("MnemonicToByteArray with %d words = %v; want ErrMnemonicLength", count, err)
		}
	}

	// Test with valid word count but invalid checksum
	// Create a mnemonic with valid words but wrong checksum
	validWords := []string{
		"abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
		"abandon", "abandon", "abandon", "abandon", "abandon", "invalid",
	}
	mnemonic := strings.Join(validWords, " ")

	_, err := MnemonicToByteArray(mnemonic)
	if err == nil {
		t.Error("MnemonicToByteArray with invalid checksum returned nil; want error")
	}

	// Test with valid word count but invalid word
	validWords[11] = "abandon" // Make it valid again
	invalidMnemonic := strings.Join(validWords, " ")
	// Replace one word with an invalid word
	invalidMnemonic = strings.Replace(invalidMnemonic, "abandon", "invalidword", 1)

	_, err = MnemonicToByteArray(invalidMnemonic)
	if err == nil {
		t.Error("MnemonicToByteArray with invalid word returned nil; want error")
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
