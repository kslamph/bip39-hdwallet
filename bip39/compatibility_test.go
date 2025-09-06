package bip39

import (
	"testing"
)

// TestCompatibilityFunctions tests that our compatibility functions work as expected
func TestCompatibilityFunctions(t *testing.T) {
	// Test that EntropyFromMnemonic works the same as MnemonicToByteArray
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	entropy1, err1 := MnemonicToByteArray(mnemonic)
	if err1 != nil {
		t.Errorf("MnemonicToByteArray failed: %v", err1)
	}

	entropy2, err2 := EntropyFromMnemonic(mnemonic)
	if err2 != nil {
		t.Errorf("EntropyFromMnemonic failed: %v", err2)
	}

	if string(entropy1) != string(entropy2) {
		t.Error("EntropyFromMnemonic and MnemonicToByteArray should return the same result")
	}

	// Test that GetWordList returns our wordlist
	wordList := GetWordList()
	if len(wordList) != 2048 {
		t.Errorf("GetWordList should return 2048 words, got %d", len(wordList))
	}

	// Test that GetWordIndex works
	index, ok := GetWordIndex("abandon")
	if !ok {
		t.Error("GetWordIndex should find 'abandon'")
	}
	if index != 0 {
		t.Errorf("GetWordIndex('abandon') should return 0, got %d", index)
	}

	// Test that NewSeedWithErrorChecking works
	seed, err := NewSeedWithErrorChecking(mnemonic, "TREZOR")
	if err != nil {
		t.Errorf("NewSeedWithErrorChecking failed: %v", err)
	}
	if len(seed) != 64 {
		t.Errorf("NewSeedWithErrorChecking should return 64-byte seed, got %d", len(seed))
	}
}
