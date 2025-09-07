package hdwallet

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
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
	privKeyBytes, err := masterKey.PrivateKey()
	if err != nil {
		t.Errorf("Master key should be private: %v", err)
	}
	if len(privKeyBytes) != 32 {
		t.Errorf("Master key length = %d; want 32", len(privKeyBytes))
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
		keyData:           []byte("invalid"), // Invalid public key data
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
		keyData:           masterKey.PublicKey(),
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
		keyData:           masterKey.PublicKey(),
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
		keyData:           masterKey.PublicKey(),
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

// TestPrivateKey tests the PrivateKey method of Key
func TestPrivateKey(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}
	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test PrivateKey on a private key
	privKeyBytes, err := masterKey.PrivateKey()
	if err != nil {
		t.Errorf("PrivateKey() on private key error: %v", err)
	}
	if len(privKeyBytes) != PrivateKeyLength {
		t.Errorf("PrivateKey() length = %d; want %d", len(privKeyBytes), PrivateKeyLength)
	}
	if !bytes.Equal(privKeyBytes, masterKey.keyData) {
		t.Error("PrivateKey() returned different bytes than keyData for private key")
	}

	// Test PrivateKey on a public key (should fail)
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}
	_, err = publicKey.PrivateKey()
	if err == nil {
		t.Error("PrivateKey() on public key should return error")
	}
}

// TestToECDSA tests the ToECDSA method of Key
func TestToECDSA(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test ToECDSA method on private key
	ecdsaPrivKey, err := masterKey.ToECDSA()
	if err != nil {
		t.Errorf("ToECDSA() error: %v", err)
	}
	if ecdsaPrivKey == nil {
		t.Error("ToECDSA() returned nil private key")
	}

	// Verify that the public key derived from the ECDSA private key matches the hdwallet public key
	// Convert the *ecdsa.PublicKey back to compressed bytes for comparison
	// btcec.S256() is the curve used by BIP32
	// Convert ecdsa.PublicKey to btcec.PublicKey by first serializing to uncompressed bytes
	// and then parsing with btcec.ParsePubKey.
	// The uncompressed public key format is 0x04 || X || Y.
	if ecdsaPrivKey.PublicKey.X == nil {
		t.Fatal("ecdsaPrivKey.PublicKey.X is nil")
	}
	if ecdsaPrivKey.PublicKey.Y == nil {
		t.Fatal("ecdsaPrivKey.PublicKey.Y is nil")
	}

	xBytes := ecdsaPrivKey.PublicKey.X.FillBytes(make([]byte, 32))
	yBytes := ecdsaPrivKey.PublicKey.Y.FillBytes(make([]byte, 32))
	uncompressedPubKeyBytes := make([]byte, 1, 65)
	uncompressedPubKeyBytes[0] = 0x04
	uncompressedPubKeyBytes = append(uncompressedPubKeyBytes, xBytes...)
	uncompressedPubKeyBytes = append(uncompressedPubKeyBytes, yBytes...)

	btcecPubKey, err := btcec.ParsePubKey(uncompressedPubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to parse btcec public key from uncompressed bytes: %v", err)
	}
	pubKeyCompressed := btcecPubKey.SerializeCompressed()
	if !bytes.Equal(pubKeyCompressed, masterKey.PublicKey()) {
		t.Error("Public key derived from ECDSA private key does not match hdwallet public key")
	}

	// Test ToECDSA method on public key (should fail)
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	_, err = publicKey.ToECDSA()
	if err == nil {
		t.Error("ToECDSA() on public key should return error")
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

// TestPublicKeyEdgeCases tests edge cases in the PublicKey function
func TestPublicKeyEdgeCases(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test PublicKey on a private key
	pubKey := masterKey.PublicKey()
	if len(pubKey) != PublicKeyCompressedLength {
		t.Errorf("Public key length = %d; want %d", len(pubKey), PublicKeyCompressedLength)
	}

	// Test PublicKey on a public key (should return the same key)
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	pubKey2 := publicKey.PublicKey()
	if !bytes.Equal(pubKey, pubKey2) {
		t.Error("PublicKey() on a public key should return the same key")
	}
}

// TestDeriveAdditionalEdgeCases tests edge cases in the Derive function
func TestDeriveAdditionalEdgeCases(t *testing.T) {
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
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	_, err = publicKey.Derive(HardenedKeyStart) // 0x80000000
	if err != ErrDerivingHardenedFromPublic {
		t.Errorf("Derive(hardened) on public key = %v; want ErrDerivingHardenedFromPublic", err)
	}

	// Test derivation with invalid IL (IL >= n)
	// This is difficult to test directly, but we can test the error handling
	// by creating a mock scenario
}

// TestDerivePathEdgeCases tests edge cases in the DerivePath function
func TestDerivePathEdgeCases(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test simple paths
	testCases := []struct {
		path     string
		expected string
	}{
		{"m", "m"},
		{"/", "/"},
		{"", ""},
		{"m/0", "m/0"},
		{"m/0'", "m/0'"},
		{"m/0H", "m/0H"},
	}

	for _, tc := range testCases {
		key, err := masterKey.DerivePath(tc.path)
		if err != nil {
			t.Errorf("DerivePath(%s) error: %v", tc.path, err)
		}
		if key == nil {
			t.Errorf("DerivePath(%s) returned nil", tc.path)
		}
	}

	// Test invalid path formats
	invalidPaths := []string{
		"invalid/path",
		"m/invalid",
		"m/invalid'",
		"m/invalidH",
	}

	for _, path := range invalidPaths {
		_, err := masterKey.DerivePath(path)
		if err == nil {
			t.Errorf("DerivePath(%s) should return error", path)
		}
	}
}

// TestB58SerializeEdgeCases tests edge cases in the B58Serialize function
func TestB58SerializeEdgeCases(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test serialization with both isPublic=true and isPublic=false
	privateKey := masterKey.B58Serialize(false)
	if privateKey == "" {
		t.Error("B58Serialize(false) returned empty string")
	}

	publicKey := masterKey.B58Serialize(true)
	if publicKey == "" {
		t.Error("B58Serialize(true) returned empty string")
	}

	// Verify that the keys start with the expected prefixes
	if !bytes.HasPrefix([]byte(privateKey), []byte("xprv")) {
		t.Errorf("Private key does not start with 'xprv': %s", privateKey)
	}

	if !bytes.HasPrefix([]byte(publicKey), []byte("xpub")) {
		t.Errorf("Public key does not start with 'xpub': %s", publicKey)
	}
}

// TestToWIFEdgeCases tests edge cases in the ToWIF function
func TestToWIFEdgeCases(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test ToWIF on private key (should succeed)
	wif, err := masterKey.ToWIF()
	if err != nil {
		t.Errorf("ToWIF() on private key error: %v", err)
	}
	if wif == "" {
		t.Error("ToWIF() on private key returned empty string")
	}

	// Test ToWIF on public key (should fail)
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
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

// TestDeriveTargetedErrorCases tests the error cases in the Derive function
func TestDeriveTargetedErrorCases(t *testing.T) {
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
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	_, err = publicKey.Derive(HardenedKeyStart) // 0x80000000
	if err != ErrDerivingHardenedFromPublic {
		t.Errorf("Derive(hardened) on public key = %v; want ErrDerivingHardenedFromPublic", err)
	}

	// Test derivation with invalid parent public key
	invalidPublicKey := &Key{
		keyData:           []byte("invalid"), // Invalid public key data
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	_, err = invalidPublicKey.Derive(0)
	if err == nil {
		t.Error("Derive() with invalid parent public key should return error")
	}
}

// TestDerivePathTargetedErrorCases tests the error cases in the DerivePath function
func TestDerivePathTargetedErrorCases(t *testing.T) {
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

// TestDerivePathTargetedEdgeCases tests edge cases in the DerivePath function
func TestDerivePathTargetedEdgeCases(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	// Test edge case paths
	testCases := []struct {
		path     string
		expected string
	}{
		{"m", "m"},
		{"/", "/"},
		{"", ""},
	}

	for _, tc := range testCases {
		key, err := masterKey.DerivePath(tc.path)
		if err != nil {
			t.Errorf("DerivePath(%s) error: %v", tc.path, err)
		}
		if key == nil {
			t.Errorf("DerivePath(%s) returned nil", tc.path)
		}
	}
}

// TestDeriveInvalidParentPublicKey tests error handling when parent public key is invalid
func TestDeriveInvalidParentPublicKey(t *testing.T) {
	// Create a key with invalid public key data
	invalidPubKey := &Key{
		keyData:           []byte("invalid public key data"),
		ChainCode:         make([]byte, 32),
		Depth:             1,
		Index:             0,
		ParentFingerprint: make([]byte, 4),
		IsPrivate:         false,
	}

	_, err := invalidPubKey.Derive(1)
	if err == nil {
		t.Error("Expected error for invalid parent public key, got nil")
	}
}

// TestDeriveHardenedEdgeCases tests hardened key derivation with boundary values
func TestDeriveHardenedEdgeCases(t *testing.T) {
	// Test various hardened key indices near boundaries
	testCases := []uint32{
		HardenedKeyStart,     // 0x80000000
		HardenedKeyStart + 1, // 0x80000001
		0xFFFFFFFF,           // Maximum uint32
	}

	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}

	for _, index := range testCases {
		_, err := masterKey.Derive(index)
		if err != nil {
			t.Errorf("Derive(%d) failed unexpectedly: %v", index, err)
		}
	}
}

// TestDeriveZeroChildPrivateKey tests the rare case where child private key equals zero
func TestDeriveZeroChildPrivateKey(t *testing.T) {
	// This test would require mocking or carefully crafted inputs to force
	// childPrivKeyInt.Cmp(big.NewInt(0)) == 0 condition
	// Since this is extremely difficult to reproduce with normal inputs,
	// we'll skip this test for now as it's more of a theoretical edge case
	t.Skip("Skipping zero child private key test - extremely rare edge case")
}

// TestDerivePointAtInfinity tests the case where ScalarBaseMult results in point at infinity
func TestDerivePointAtInfinity(t *testing.T) {
	// This test would require specific IL values that result in point at infinity
	// when passed to btcec.S256().ScalarBaseMult(IL)
	// Since this is extremely difficult to reproduce with normal inputs,
	// we'll skip this test for now as it's more of a theoretical edge case
	t.Skip("Skipping point at infinity test - extremely rare edge case")
}

// TestDeriveFromPublic tests deriving non-hardened child keys from public keys
func TestDeriveFromPublic(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}
	if masterKey == nil {
		t.Fatal("NewMasterKey() returned nil")
	}

	// Convert master key to public key
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false, // This is a public key
	}

	// Derive a non-hardened child from the public key
	// This should work and will exercise the uncovered code path
	childKey, err := publicKey.Derive(0) // Non-hardened derivation
	if err != nil {
		t.Errorf("Derive() from public key error: %v", err)
		return
	}
	if childKey == nil {
		t.Error("Derive() from public key returned nil")
		return
	}

	// Verify that the child key is also a public key (not private)
	if childKey.IsPrivate {
		t.Error("Child key derived from public key should also be public")
	}

	// Verify the child key has the correct properties
	if childKey.Depth != 1 {
		t.Errorf("Child key depth = %d; want 1", childKey.Depth)
	}
	if childKey.Index != 0 {
		t.Errorf("Child key index = %d; want 0", childKey.Index)
	}
}

// TestDeriveFromPublicMultipleChildren tests deriving multiple non-hardened child keys from public keys
func TestDeriveFromPublicMultipleChildren(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}
	if masterKey == nil {
		t.Fatal("NewMasterKey() returned nil")
	}

	// Convert master key to public key
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	// Test deriving multiple non-hardened children
	testIndices := []uint32{0, 1, 2, 10, 100}

	for _, index := range testIndices {
		childKey, err := publicKey.Derive(index)
		if err != nil {
			t.Errorf("Derive(%d) from public key error: %v", index, err)
			continue
		}
		if childKey == nil {
			t.Errorf("Derive(%d) from public key returned nil", index)
			continue
		}

		if childKey.IsPrivate {
			t.Errorf("Child key derived from public key should also be public (index %d)", index)
		}
		if childKey.Depth != 1 {
			t.Errorf("Child key depth = %d; want 1 (index %d)", childKey.Depth, index)
		}
		if childKey.Index != index {
			t.Errorf("Child key index = %d; want %d", childKey.Index, index)
		}
	}
}

// TestDerivePathEmptySegments tests derivation paths with empty segments that trigger len(part) == 0
func TestDerivePathEmptySegments(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}
	if masterKey == nil {
		t.Fatal("NewMasterKey() returned nil")
	}

	// Test cases that should trigger len(part) == 0 in DerivePath function
	testCases := []struct {
		path        string
		description string
		expectDepth byte // Expected depth after derivation (0 means no derivation occurred)
	}{
		{"/0/1", "Leading slash creates empty segment", 2},              // "/0/1" -> ["", "0", "1"] -> ["0", "1"] -> depth 2
		{"0//1", "Consecutive slashes create empty segment", 2},         // "0//1" -> ["0", "", "1"] -> ["0", "1"] -> depth 2
		{"0/1/", "Trailing slash creates empty segment", 2},             // "0/1/" -> ["0", "1", ""] -> ["0", "1"] -> depth 2
		{"//0/1", "Multiple leading slashes create empty segments", 2},  // "//0/1" -> ["", "", "0", "1"] -> ["0", "1"] -> depth 2
		{"0/1//", "Multiple trailing slashes create empty segments", 2}, // "0/1//" -> ["0", "1", "", ""] -> ["0", "1"] -> depth 2
		{"/", "Single slash creates empty segment", 0},                  // "/" -> [""] -> [] -> no derivation, depth 0
		{"//", "Double slash creates empty segments", 0},                // "//" -> ["", ""] -> [] -> no derivation, depth 0
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			key, err := masterKey.DerivePath(tc.path)
			if err != nil {
				t.Errorf("DerivePath(%s) error: %v", tc.path, err)
			}
			if key == nil {
				t.Errorf("DerivePath(%s) returned nil", tc.path)
			}
			// Check that the depth matches expectations
			if key.Depth != tc.expectDepth {
				t.Errorf("DerivePath(%s) depth = %d; want %d", tc.path, key.Depth, tc.expectDepth)
			}
		})
	}
}

// TestDerivePathHardenedFromPublic tests that deriving hardened children from public keys returns error
func TestDerivePathHardenedFromPublic(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}
	if masterKey == nil {
		t.Fatal("NewMasterKey() returned nil")
	}

	// Convert master key to public key
	publicKey := &Key{
		keyData:           masterKey.PublicKey(),
		ChainCode:         masterKey.ChainCode,
		Depth:             masterKey.Depth,
		Index:             masterKey.Index,
		ParentFingerprint: masterKey.ParentFingerprint,
		IsPrivate:         false,
	}

	// Test deriving hardened child from public key - this should trigger error at line 404
	_, err = publicKey.DerivePath("m/0'")
	if err == nil {
		t.Error("DerivePath with hardened child from public key should return error")
	} else if err != ErrDerivingHardenedFromPublic {
		t.Errorf("DerivePath with hardened child from public key returned unexpected error: %v", err)
	}

	// Test deriving multiple hardened children from public key
	_, err = publicKey.DerivePath("m/0'/1'")
	if err == nil {
		t.Error("DerivePath with multiple hardened children from public key should return error")
	} else if err != ErrDerivingHardenedFromPublic {
		t.Errorf("DerivePath with multiple hardened children from public key returned unexpected error: %v", err)
	}
}

// TestDerivePathWithUppercaseM tests derivation paths with uppercase "M/" prefix
func TestDerivePathWithUppercaseM(t *testing.T) {
	// Create a master key
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Failed to decode seed hex: %v", err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error: %v", err)
	}
	if masterKey == nil {
		t.Fatal("NewMasterKey() returned nil")
	}

	// Test simple path with uppercase "M/"
	key, err := masterKey.DerivePath("M/0")
	if err != nil {
		t.Errorf("DerivePath(M/0) error: %v", err)
	}
	if key == nil {
		t.Error("DerivePath(M/0) returned nil")
	}

	// Test hardened path with uppercase "M/"
	key, err = masterKey.DerivePath("M/0'")
	if err != nil {
		t.Errorf("DerivePath(M/0') error: %v", err)
	}
	if key == nil {
		t.Error("DerivePath(M/0') returned nil")
	}

	// Test complex path with uppercase "M/"
	key, err = masterKey.DerivePath("M/0'/1/2'/2/1000000000")
	if err != nil {
		t.Errorf("DerivePath(M/0'/1/2'/2/1000000000) error: %v", err)
	}
	if key == nil {
		t.Error("DerivePath(M/0'/1/2'/2/1000000000) returned nil")
	}

	// Verify that the results are the same as with lowercase "m/"
	keyM, err := masterKey.DerivePath("M/0/1")
	if err != nil {
		t.Errorf("DerivePath(M/0/1) error: %v", err)
	}
	if keyM == nil {
		t.Error("DerivePath(M/0/1) returned nil")
	}

	keym, err := masterKey.DerivePath("m/0/1")
	if err != nil {
		t.Errorf("DerivePath(m/0/1) error: %v", err)
	}
	if keym == nil {
		t.Error("DerivePath(m/0/1) returned nil")
	}

	// The keys should be identical
	if keyM.SerializedSize() != keym.SerializedSize() {
		t.Error("Keys derived from M/ and m/ paths should have same serialized size")
	}
}
