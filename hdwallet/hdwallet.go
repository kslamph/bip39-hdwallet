package hdwallet

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv" // Added for DerivePath parsing
	"strings" // Added for path parsing

	"golang.org/x/crypto/ripemd160"
	"github.com/btcsuite/btcd/btcutil/base58" // Will use base58.Encode only
	"github.com/btcsuite/btcd/btcec/v2"      // Added btcec/v2
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

// Key represents a BIP32 key
type Key struct {
	Key       []byte // 33 bytes (compressed public key) or 32 bytes (private key)
	ChainCode []byte // 32 bytes
	Depth     byte   // 1 byte
	Index     uint32 // 4 bytes
	ParentFingerprint []byte // 4 bytes
	IsPrivate             bool
}

// NewMasterKey creates a new master key from a seed
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
		Key:               IL,
		ChainCode:         IR,
		Depth:             0x00,
		Index:             0x00000000,
		ParentFingerprint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:         true,
	}

	return key, nil
}

// PublicKey returns the public key for this key
func (k *Key) PublicKey() []byte {
	if !k.IsPrivate {
		return k.Key
	}

	privKey, _ := btcec.PrivKeyFromBytes(k.Key)
	pubKey := privKey.PubKey().SerializeCompressed()
	return pubKey
}

// Fingerprint returns the key fingerprint
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

// Derive derives a child key at the given index
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
		copy(data[1:], k.Key) // k.Key is private key here
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
	if ilInt.Cmp(btcec.S256().N) >= 0 {
		// This should theoretically not happen with HMAC-SHA512 output
		return nil, ErrInvalidKey // Or, per spec, increment index and try again
	}

	var childKeyBytes []byte
	var isPrivateChild bool

	if k.IsPrivate {
		// Private parent key -> private child key
		// k_i = (IL + k_par) mod n
		parentPrivKeyInt := new(big.Int).SetBytes(k.Key) // k.Key is parent private key
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
		parentPubKey, err := btcec.ParsePubKey(k.Key) // k.Key is parent public key
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
		Key:               childKeyBytes,
		ChainCode:         IR,
		Depth:             k.Depth + 1,
		Index:             index,
		ParentFingerprint: k.Fingerprint(),
		IsPrivate:         isPrivateChild,
	}

	return child, nil
}

// DerivePath derives a child key at the given path
// Path should be in the format "m/44'/0'/0'/0/0"
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

// String returns a string representation of the key
func (k *Key) String() string {
	if k.IsPrivate {
		return fmt.Sprintf("Private key: %x, Chain code: %x", k.Key, k.ChainCode)
	}
	return fmt.Sprintf("Public key: %x, Chain code: %x", k.Key, k.ChainCode)
}

// SerializedSize returns the size of the serialized key
func (k *Key) SerializedSize() int {
	if k.IsPrivate {
		return 78 // 1 + 32 + 32 + 1 + 4 + 4 + 33
	}
	return 78 // 1 + 32 + 32 + 1 + 4 + 4 + 33
}

// B58Serialize serializes the extended key into a Base58Check-encoded string.
// If isPublic is true, it serializes the extended public key; otherwise, it serializes the extended private key.
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
		copy(keyData[1:], k.Key)
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