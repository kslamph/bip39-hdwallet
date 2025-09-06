// Package hdwallet implements the BIP32 and BIP44 specifications for hierarchical deterministic wallets.
// BIP32 defines a method for creating a hierarchical deterministic wallet, where keys are derived
// from a single master key using a tree structure. BIP44 defines a specific derivation path
// structure for interoperability between wallets.
//
// The implementation includes:
//   - Creating master keys from seeds
//   - Deriving child keys (normal and hardened)
//   - Deriving keys using derivation paths
//   - Support for BIP44 standard paths
//   - Serialization to Base58Check format (xprv/xpub)
//   - Conversion to Wallet Import Format (WIF)
//
// For more information, see:
//   - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//   - https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
package hdwallet

import (
	"crypto/ecdsa" // Added for ToECDSA method
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv" // Added for DerivePath parsing
	"strings" // Added for path parsing

	"github.com/btcsuite/btcd/btcec/v2"       // Added btcec/v2
	"github.com/btcsuite/btcd/btcutil/base58" // Will use base58.Encode only
	"golang.org/x/crypto/ripemd160"
)

const (
	// HardenedKeyStart is the index where hardened keys start
	HardenedKeyStart = 0x80000000

	// FirstHardenedChild is the index of the first hardened child
	FirstHardenedChild = HardenedKeyStart

	// PublicKeyCompressedLength is the length of a compressed public key
	PublicKeyCompressedLength = 33

	// PrivateKeyLength is the length of a private key
	PrivateKeyLength = 32
)

var (
	// ErrInvalidKey is returned when a key is invalid
	ErrInvalidKey = errors.New("hdwallet: invalid key")

	// ErrInvalidSeed is returned when a seed is invalid
	ErrInvalidSeed = errors.New("hdwallet: invalid seed")

	// ErrDerivingHardenedFromPublic is returned when trying to derive a hardened child from a public key
	ErrDerivingHardenedFromPublic = errors.New("hdwallet: cannot derive hardened child from public key")

	// ErrInvalidPath is returned when a derivation path is invalid
	ErrInvalidPath = errors.New("hdwallet: invalid derivation path")

	// ErrInvalidCurve is returned when the curve is invalid
	ErrInvalidCurve = errors.New("hdwallet: invalid curve")
)

// Key represents a BIP32 hierarchical deterministic wallet key.
// It contains all the information needed to derive child keys and serialize
// the key in various formats.
type Key struct {
	// keyData holds the actual key bytes. It can be a 33-byte compressed public key
	// or a 32-byte private key, distinguished by the IsPrivate field.
	keyData []byte

	// ChainCode is the 32-byte chain code used in key derivation.
	ChainCode []byte

	// Depth is the key derivation depth (0 for master key).
	Depth byte

	// Index is the child index of this key (0x80000000 or higher for hardened keys).
	Index uint32

	// ParentFingerprint is the first 4 bytes of the parent key's hash.
	ParentFingerprint []byte

	// IsPrivate indicates whether this Key holds a private key (true) or a public key (false).
	IsPrivate bool
}

// NewMasterKey creates a new master key from a seed according to the BIP32 specification.
// The seed must be between 16 and 64 bytes as per BIP32 requirements.
//
// This function implements the master key generation algorithm:
//  1. Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
//  2. Split I into two 32-byte sequences, IL and IR
//  3. Use IL as master secret key, and IR as master chain code
//  4. Verify that IL is in the range [1, n-1] where n is the curve order
//
// Parameters:
//
//	seed: A cryptographically secure random seed between 16-64 bytes
//
// Returns:
//
//	*Key: A new master key that can be used to derive child keys
//	error: ErrInvalidSeed if seed length is invalid, or ErrInvalidKey if the generated key is invalid
func NewMasterKey(seed []byte) (*Key, error) {
	// Master key is always private
	if len(seed) < 16 || len(seed) > 64 {
		return nil, ErrInvalidSeed
	}

	// Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	h.Write(seed)
	I := h.Sum(nil)

	// Split I into two 32-byte sequences
	IL := I[:32]
	IR := I[32:]

	// The private key cannot be zero or greater than/equal to the curve order N
	privKeyInt := new(big.Int).SetBytes(IL)
	if privKeyInt.Cmp(big.NewInt(0)) == 0 || privKeyInt.Cmp(btcec.S256().N) >= 0 {
		return nil, ErrInvalidKey
	}

	key := &Key{
		keyData:           IL,
		ChainCode:         IR,
		Depth:             0x00,
		Index:             0x00000000,
		ParentFingerprint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:         true,
	}

	return key, nil
}

// PublicKey returns the compressed public key for this key.
// If the key is already a public key, it returns the keyData directly.
// If the key is a private key, it derives and returns the corresponding compressed public key.
// This method ensures that a 33-byte compressed public key is always returned.
//
// Returns:
//
//	[]byte: The 33-byte compressed public key.
func (k *Key) PublicKey() []byte {
	if !k.IsPrivate {
		return k.keyData
	}

	// Derive public key from private key
	privKey, _ := btcec.PrivKeyFromBytes(k.keyData)
	pubKey := privKey.PubKey().SerializeCompressed()
	return pubKey
}

// PrivateKey returns the raw 32-byte private key bytes if this Key is a private key.
// This method explicitly indicates that the key is intended for private operations.
//
// Returns:
//
//	[]byte: The 32-byte private key.
//	error: An error if the Key is not a private key (i.e., IsPrivate is false).
func (k *Key) PrivateKey() ([]byte, error) {
	if !k.IsPrivate {
		return nil, fmt.Errorf("hdwallet: Key is not a private key")
	}
	return k.keyData, nil
}

// ToECDSA converts the private key to a standard *ecdsa.PrivateKey object.
// This method is useful for integrating with other Go cryptography functions that
// expect the standard library's ECDSA private key type.
//
// Returns:
//
//	*ecdsa.PrivateKey: The standard library ECDSA private key.
//	error: An error if the Key is not a private key or if the conversion fails.
func (k *Key) ToECDSA() (*ecdsa.PrivateKey, error) {
	if !k.IsPrivate {
		return nil, fmt.Errorf("hdwallet: cannot convert public Key to ECDSA private key")
	}
	privKey, _ := btcec.PrivKeyFromBytes(k.keyData)
	return privKey.ToECDSA(), nil
}

// Fingerprint returns the key fingerprint as the first 4 bytes of the RIPEMD-160 hash
// of the SHA-256 hash of the public key, as specified in BIP32.
// This fingerprint is used to identify the parent key in child key derivation.
//
// The algorithm follows BIP32 specification:
//  1. Serialize the public key in compressed format
//  2. Perform SHA-256 hashing on the public key
//  3. Perform RIPEMD-160 hashing on the SHA-256 hash
//  4. Return the first 4 bytes of the RIPEMD-160 hash
//
// Returns:
//
//	[]byte: The 4-byte key fingerprint
func (k *Key) Fingerprint() []byte {
	pubKey := k.PublicKey()
	// Perform SHA256 hashing on the public key
	// Then RIPEMD-160 hashing on the result
	pubKeyHash := sha256.Sum256(pubKey)
	ripe := ripemd160.New()
	ripe.Write(pubKeyHash[:])
	fingerprint := ripe.Sum(nil)

	// Return the first 4 bytes
	return fingerprint[:4]
}

// Derive derives a child key at the given index according to the BIP32 specification.
// The index can be a normal child (0-0x7FFFFFFF) or a hardened child (0x80000000-0xFFFFFFFF).
//
// For normal child derivation:
//   - Data = serP(Kpar) || ser32(i)
//   - Uses the parent's public key
//
// For hardened child derivation:
//   - Data = 0x00 || ser256(kpar) || ser32(i)
//   - Uses the parent's private key and can only be done with private keys
//
// Parameters:
//
//	index: The child index to derive. Use HardenedKeyStart (0x80000000) or higher for hardened keys
//
// Returns:
//
//	*Key: The derived child key
//	error: ErrDerivingHardenedFromPublic if trying to derive a hardened child from a public key,
//	       or ErrInvalidKey if the derived key is invalid
func (k *Key) Derive(index uint32) (*Key, error) {
	// Prepare the data to be hashed
	var data []byte

	// Hardened child (i >= 0x80000000)
	if index >= HardenedKeyStart {
		// If parent is public, cannot derive hardened child
		if !k.IsPrivate {
			return nil, ErrDerivingHardenedFromPublic
		}
		// Data = 0x00 || ser256(kpar) || ser32(i)
		data = make([]byte, 37)
		data[0] = 0x00
		copy(data[1:], k.keyData) // k.keyData is private key here
		binary.BigEndian.PutUint32(data[33:], index)
	} else {
		// Normal child (i < 0x80000000)
		// Data = serP(Kpar) || ser32(i)
		data = make([]byte, 37)
		copy(data, k.PublicKey()) // k.PublicKey() returns compressed public key
		binary.BigEndian.PutUint32(data[33:], index)
	}

	// Calculate I = HMAC-SHA512(Key = cpar, Data = Data)
	h := hmac.New(sha512.New, k.ChainCode)
	h.Write(data)
	I := h.Sum(nil)

	// Split I into two 32-byte sequences, IL and IR
	IL := I[:32]
	IR := I[32:]

	// Parse IL as a 256-bit integer
	ilInt := new(big.Int).SetBytes(IL)

	// Check if IL is valid (IL < n)
	// This should theoretically not happen with HMAC-SHA512 output
	if ilInt.Cmp(btcec.S256().N) >= 0 {
		return nil, ErrInvalidKey // Or, per spec, increment index and try again
	}

	var childKeyBytes []byte
	var isPrivateChild bool

	if k.IsPrivate {
		// Private parent key -> private child key
		// k_i = (IL + k_par) mod n
		parentPrivKeyInt := new(big.Int).SetBytes(k.keyData) // k.keyData is parent private key
		childPrivKeyInt := new(big.Int).Add(ilInt, parentPrivKeyInt)
		childPrivKeyInt.Mod(childPrivKeyInt, btcec.S256().N) // mod n

		// Check if child private key is valid (0 < childPrivKeyInt < n)
		if childPrivKeyInt.Cmp(big.NewInt(0)) == 0 || childPrivKeyInt.Cmp(btcec.S256().N) >= 0 {
			return nil, ErrInvalidKey // Or, per spec, increment index and try again
		}

		childKeyBytes = childPrivKeyInt.FillBytes(make([]byte, PrivateKeyLength)) // Pad to 32 bytes
		isPrivateChild = true
	} else {
		// Public parent key -> public child key (only for non-hardened children)
		// K_i = point(IL) + K_par
		if index >= HardenedKeyStart {
			return nil, ErrDerivingHardenedFromPublic // Should have been caught earlier
		}

		// Convert IL to a point on the curve
		// K_i = point(IL)
		ilPointX, ilPointY := btcec.S256().ScalarBaseMult(IL)
		if ilPointX == nil { // point(IL) is the point at infinity
			return nil, ErrInvalidKey
		}

		// Add parent public key K_par to point(IL)
		parentPubKey, err := btcec.ParsePubKey(k.keyData) // k.keyData is parent public key
		if err != nil {
			return nil, err // Invalid parent public key
		}

		childPubKeyX, childPubKeyY := btcec.S256().Add(ilPointX, ilPointY, parentPubKey.X(), parentPubKey.Y())

		// Serialize compressed
		// Manually create compressed public key bytes from X and Y coordinates.
		childKeyBytes = make([]byte, PublicKeyCompressedLength)
		if childPubKeyY.Bit(0) == 0 { // Y is even
			childKeyBytes[0] = 0x02
		} else { // Y is odd
			childKeyBytes[0] = 0x03
		}
		childPubKeyX.FillBytes(childKeyBytes[1:]) // X coordinate
		isPrivateChild = false
	}

	// Create the child key
	child := &Key{
		keyData:           childKeyBytes,
		ChainCode:         IR,
		Depth:             k.Depth + 1,
		Index:             index,
		ParentFingerprint: k.Fingerprint(),
		IsPrivate:         isPrivateChild,
	}

	return child, nil
}

// DerivePath derives a child key at the given path according to BIP32/BIP44 specifications.
// Path should be in the format "m/44'/0'/0'/0/0" where:
//   - m: Master key
//   - 44': BIP44 purpose (hardened)
//   - 0': Coin type (hardened, 0 for Bitcoin)
//   - 0': Account number (hardened)
//   - 0: Change chain (0 for external, 1 for internal)
//   - 0: Address index
//
// Hardened indices are denoted with either an apostrophe (') or 'H'.
//
// Parameters:
//
//	path: The derivation path string in BIP32/BIP44 format
//
// Returns:
//
//	*Key: The derived child key at the specified path
//	error: ErrInvalidPath for invalid path formats, or errors from the Derive method
func (k *Key) DerivePath(path string) (*Key, error) {
	if path == "m" || path == "/" || path == "" {
		return k, nil
	}

	// Split the path
	parts := []string{}
	// Check for "m/" prefix only if it's the master path
	if strings.HasPrefix(path, "m/") {
		path = path[2:]
	} else if strings.HasPrefix(path, "M/") { // BIP32 often uses M for master public, handle that too
		path = path[2:]
	}

	// Split by "/"
	splitParts := strings.Split(path, "/")
	for _, part := range splitParts {
		if len(part) == 0 {
			continue
		}
		parts = append(parts, part)
	}

	// Derive each part
	key := k
	for _, part := range parts {
		var index uint32
		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "H") { // Check for hardened keys
			// Hardened key
			parsedPart := strings.TrimSuffix(strings.TrimSuffix(part, "H"), "'")
			val, err := strconv.ParseUint(parsedPart, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid hardened child index '%s'", ErrInvalidPath, part)
			}
			index = uint32(val) + HardenedKeyStart
		} else {
			// Normal key
			val, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid child index '%s'", ErrInvalidPath, part)
			}
			index = uint32(val)
		}

		child, err := key.Derive(index)
		if err != nil {
			return nil, err
		}
		key = child
	}

	return key, nil
}

// String returns a human-readable string representation of the key.
// It displays the type of key (private or public) along with its key data and chain code.
// This method is primarily intended for debugging and logging purposes.
func (k *Key) String() string {
	if k.IsPrivate {
		return fmt.Sprintf("Private Key: %x, Chain Code: %x", k.keyData, k.ChainCode)
	}
	return fmt.Sprintf("Public Key: %x, Chain Code: %x", k.keyData, k.ChainCode)
}

// SerializedSize returns the size in bytes of the serialized extended key.
// Both private and public extended keys serialize to 78 bytes as per BIP32 specification.
// The serialization format consists of:
//   - 4 bytes: version
//   - 1 byte: depth
//   - 4 bytes: parent fingerprint
//   - 4 bytes: child number
//   - 32 bytes: chain code
//   - 33 bytes: key data (public key or 0x00 + private key)
func (k *Key) SerializedSize() int {
	// Both private and public extended keys have the same serialized size
	return 78 // 4 + 1 + 4 + 4 + 32 + 33 = 78 bytes
}

// B58Serialize serializes the extended key into a Base58Check-encoded string.
// If isPublic is true, it serializes the extended public key; otherwise, it serializes the extended private key.
// The serialized format follows the BIP32 specification with version bytes:
//   - xprv prefix for private keys (0x0488ADE4)
//   - xpub prefix for public keys (0x0488B21E)
//
// Parameters:
//
//	isPublic: If true, serialize as extended public key; if false, serialize as extended private key
//
// Returns:
//
//	Base58Check-encoded string representation of the extended key
func (k *Key) B58Serialize(isPublic bool) string {
	// 4 bytes: version bytes
	// mainnet: 0x0488B21E public, 0x0488ADE4 private
	var versionBytes []byte
	if isPublic {
		versionBytes = []byte{0x04, 0x88, 0xB2, 0x1E} // xpub
	} else {
		versionBytes = []byte{0x04, 0x88, 0xAD, 0xE4} // xprv
	}

	// 1 byte: depth
	depth := []byte{k.Depth}

	// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
	parentFingerprint := k.ParentFingerprint

	// 4 bytes: child number.
	childIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(childIndex, k.Index)

	// 32 bytes: the chain code
	chainCode := k.ChainCode

	// 33 bytes: the public key or private key data
	var keyData []byte
	if isPublic {
		keyData = k.PublicKey()
	} else {
		keyData = make([]byte, 33)
		keyData[0] = 0x00 // Private key prefix
		copy(keyData[1:], k.keyData)
	}

	// Concatenate all parts into a 78-byte payload
	payload := make([]byte, 0, 78)
	payload = append(payload, versionBytes...)
	payload = append(payload, depth...)
	payload = append(payload, parentFingerprint...)
	payload = append(payload, childIndex...)
	payload = append(payload, chainCode...)
	payload = append(payload, keyData...)

	// Double SHA256 checksum
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4] // First 4 bytes of the double hash

	// Append checksum to payload
	finalData := append(payload, checksum...)

	// Base58 encode the result
	return base58.Encode(finalData)
}

// ToWIF converts a private key to Wallet Import Format (WIF).
// WIF is a format for encoding Bitcoin private keys that includes
// a version byte, the private key, and a checksum.
//
// This method only works on private keys. Attempting to convert
// a public key will return an error.
//
// Returns:
//
//	string: The WIF-encoded private key with a '5' prefix for mainnet
//	error:  An error if the key is not a private key
func (k *Key) ToWIF() (string, error) {
	if !k.IsPrivate {
		return "", fmt.Errorf("cannot convert public key to WIF")
	}

	// For mainnet Bitcoin, the prefix is 0x80.
	// For compressed WIF, append 0x01.
	// This assumes the public key is compressed, which is standard for BIP44.
	wifBytes := make([]byte, 0, PrivateKeyLength+2)
	wifBytes = append(wifBytes, 0x80) // Mainnet prefix
	wifBytes = append(wifBytes, k.keyData...)
	wifBytes = append(wifBytes, 0x01) // Compressed public key marker

	// Double SHA256 hash for checksum
	firstHash := sha256.Sum256(wifBytes)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]
	// Append checksum and Base58 encode
	finalData := append(wifBytes, checksum...)
	return base58.Encode(finalData), nil
}

