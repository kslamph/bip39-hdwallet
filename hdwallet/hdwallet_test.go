package hdwallet

import (
	"bytes"
	"encoding/hex"
	"strings"
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

// TestNewMasterKeyErrors tests error conditions in NewMasterKey
func TestNewMasterKeyErrors(t *testing.T) {
	// Test with invalid seed lengths
	invalidLengths := []int{0, 1, 15, 65, 100}
	
	for _, length := range invalidLengths {
		seed := make([]byte, length)
		_, err := NewMasterKey(seed)
		if err != ErrInvalidSeed {
			t.Errorf("NewMasterKey with %d-byte seed = %v; want ErrInvalidSeed", length, err)
		}
	}
	
	// Test with valid length but zero entropy (edge case)
	// This is difficult to test because we can't easily create a seed that would
	// result in a private key of zero or >= curve order N
	// We'll just note that this line is not covered
	// t.Skip("Skipping test for zero private key - would require complex seed manipulation")
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

// TestDeriveEdgeCases tests edge cases in Derive
func TestDeriveEdgeCases(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test derivation of hardened child from public key (should fail)
	// This is already tested in TestDeriveErrors
	
	// Test derivation with invalid parent public key
	// Create a public key with invalid data
	invalidPublicKey := &Key{
		Key:               []byte("invalid"), // Invalid public key data
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	// Try to derive a normal child from the invalid public key
	_, err = invalidPublicKey.Derive(0)
	if err == nil {
		t.Error("Derive() with invalid parent public key should return error")
	}
}

// TestDeriveErrors tests error conditions in Derive
func TestDeriveErrors(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test derivation of hardened child from public key (should fail)
	// Create a public key
	publicKey := &Key{
		Key:               masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	// Try to derive a hardened child from the public key
	_, err = publicKey.Derive(HardenedKeyStart) // 0x80000000
	if err != ErrDerivingHardenedFromPublic {
		t.Errorf("Derive(hardened) on public key = %v; want ErrDerivingHardenedFromPublic", err)
	}
}

// TestDerivePathErrors tests error conditions in DerivePath
func TestDerivePathErrors(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test with invalid path format
	_, err = masterKey.DerivePath("invalid/path")
	if err == nil {
		t.Error("DerivePath with invalid path should return error")
	}

	// Test with non-numeric index
	_, err = masterKey.DerivePath("m/invalid")
	if err == nil {
		t.Error("DerivePath with non-numeric index should return error")
	}

	// Test with non-numeric hardened index
	_, err = masterKey.DerivePath("m/invalid'")
	if err == nil {
		t.Error("DerivePath with non-numeric hardened index should return error")
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

// TestString tests the String method of Key
func TestString(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test String method on private key
	str := masterKey.String()
	if str == "" {
		t.Error("String() returned empty string for private key")
	}

	// Test String method on public key
	// Create a public key by deriving a child and converting to public
	publicKey := &Key{
		Key:               masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}
	
	publicStr := publicKey.String()
	if publicStr == "" {
		t.Error("String() returned empty string for public key")
	}
}

// TestSerializedSize tests the SerializedSize method of Key
func TestSerializedSize(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test SerializedSize method
	size := masterKey.SerializedSize()
	if size != 78 {
		t.Errorf("SerializedSize() = %d; want 78", size)
	}
}

// TestB58Serialize tests the B58Serialize method of Key
func TestB58Serialize(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test B58Serialize method for private key
	privateKey := masterKey.B58Serialize(false)
	if privateKey == "" {
		t.Error("B58Serialize(false) returned empty string")
	}

	// Test B58Serialize method for public key
	publicKey := masterKey.B58Serialize(true)
	if publicKey == "" {
		t.Error("B58Serialize(true) returned empty string")
	}

	// Verify that the keys start with the expected prefixes
	// xprv for private keys
	if !strings.HasPrefix(privateKey, "xprv") {
		t.Errorf("Private key does not start with 'xprv': %s", privateKey)
	}

	// xpub for public keys
	if !strings.HasPrefix(publicKey, "xpub") {
		t.Errorf("Public key does not start with 'xpub': %s", publicKey)
	}
}

// TestToWIF tests the ToWIF method of Key
func TestToWIF(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test ToWIF method on private key
	wif, err := masterKey.ToWIF()
	if err != nil {
		t.Errorf("ToWIF() error: %v", err)
	}
	if wif == "" {
		t.Error("ToWIF() returned empty string")
	}

	// Test ToWIF method on public key (should fail)
	// Create a public key by deriving a child and converting to public
	publicKey := &Key{
		Key:               masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	_, err = publicKey.ToWIF()
	if err == nil {
		t.Error("ToWIF() on public key should return error")
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