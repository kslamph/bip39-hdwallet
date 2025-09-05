package hdwallet

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNewMasterKey(t *testing.T) {
	// Test with a valid seed
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Errorf("NewMasterKey() error: %v", err)
	}

	// Check that the master key is private
	if !masterKey.IsPrivate {
		t.Error("Master key should be private")
	}

	// Check the key length
	if len(masterKey.Key) != 32 {
		t.Errorf("Master key length = %d; want 32", len(masterKey.Key))
	}

	// Check the chain code length
	if len(masterKey.ChainCode) != 32 {
		t.Errorf("Chain code length = %d; want 32", len(masterKey.ChainCode))
	}

	// Check the depth
	if masterKey.Depth != 0 {
		t.Errorf("Master key depth = %d; want 0", masterKey.Depth)
	}

	// Check the index
	if masterKey.Index != 0 {
		t.Errorf("Master key index = %d; want 0", masterKey.Index)
	}

	// Check the parent fingerprint
	expectedParentFingerprint := []byte{0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(masterKey.ParentFingerprint, expectedParentFingerprint) {
		t.Errorf("Master key parent fingerprint = %x; want %x", masterKey.ParentFingerprint, expectedParentFingerprint)
	}
}

func TestDerive(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Derive a child key
	childKey, err := masterKey.Derive(0)
	if err != nil {
		t.Errorf("Derive() error: %v", err)
	}

	// Check that the child key is private
	if !childKey.IsPrivate {
		t.Error("Child key should be private")
	}

	// Check the depth
	if childKey.Depth != 1 {
		t.Errorf("Child key depth = %d; want 1", childKey.Depth)
	}

	// Check the index
	if childKey.Index != 0 {
		t.Errorf("Child key index = %d; want 0", childKey.Index)
	}

	// Check that the parent fingerprint is set
	if len(childKey.ParentFingerprint) != 4 {
		t.Errorf("Child key parent fingerprint length = %d; want 4", len(childKey.ParentFingerprint))
	}
}

func TestDerivePath(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test simple path
	key, err := masterKey.DerivePath("m/0")
	if err != nil {
		t.Errorf("DerivePath(m/0) error: %v", err)
	}
	if key == nil {
		t.Error("DerivePath(m/0) returned nil")
	}

	// Test hardened path
	key, err = masterKey.DerivePath("m/0'")
	if err != nil {
		t.Errorf("DerivePath(m/0') error: %v", err)
	}
	if key == nil {
		t.Error("DerivePath(m/0') returned nil")
	}

	// Test complex path
	key, err = masterKey.DerivePath("m/0'/1/2'/2/1000000000")
	if err != nil {
		t.Errorf("DerivePath(m/0'/1/2'/2/1000000000) error: %v", err)
	}
	if key == nil {
		t.Error("DerivePath(m/0'/1/2'/2/1000000000) returned nil")
	}
}

func TestFingerprint(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Get the fingerprint
	fingerprint := masterKey.Fingerprint()
	if len(fingerprint) != 4 {
		t.Errorf("Fingerprint length = %d; want 4", len(fingerprint))
	}
}

func TestPublicKey(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Get the public key
	pubKey := masterKey.PublicKey()
	if len(pubKey) != PublicKeyCompressedLength {
		t.Errorf("Public key length = %d; want %d", len(pubKey), PublicKeyCompressedLength)
	}
}