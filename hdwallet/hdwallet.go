package hdwallet

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ripemd160"
	"github.com/btcsuite/btcd/btcutil/base58"
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

	// The private key cannot be zero
	zero := new(big.Int)
	privKeyInt := new(big.Int).SetBytes(IL)
	if privKeyInt.Cmp(zero) == 0 {
		return nil, ErrInvalidKey
	}

	// The private key cannot be greater than or equal to the order of the curve
	// For secp256k1, the order is 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	order := new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	})
	if privKeyInt.Cmp(order) >= 0 {
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

	// For simplicity, we're returning a placeholder
	// In a real implementation, you would derive the public key from the private key using ECDSA
	pubKey := make([]byte, PublicKeyCompressedLength)
	pubKey[0] = 0x02 // Even y-coordinate
	copy(pubKey[1:], k.Key)
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
	data := make([]byte, 37)

	// Hardened child
	if index >= HardenedKeyStart {
		// Data = 0x00 || ser256(kpar) || ser32(i)
		if !k.IsPrivate {
			return nil, ErrDerivingHardenedFromPublic
		}
		data[0] = 0x00
		copy(data[1:], k.Key)
		binary.BigEndian.PutUint32(data[33:], index)
	} else {
		// Normal child
		// Data = serP(point(kpar)) || ser32(i)
		pubKey := k.PublicKey()
		copy(data, pubKey)
		binary.BigEndian.PutUint32(data[33:], index)
	}

	// Calculate I = HMAC-SHA512(Key = cpar, Data = Data)
	h := hmac.New(sha512.New, k.ChainCode)
	h.Write(data)
	I := h.Sum(nil)

	// Split I into two 32-byte sequences
	IL := I[:32]
	IR := I[32:]

	// The returned child key ki is parse256(IL) + kpar (mod n)
	var childKey []byte
	if k.IsPrivate {
		// Private key derivation
		// childKey = (parse256(IL) + kpar) mod n
		ilInt := new(big.Int).SetBytes(IL)
		privKeyInt := new(big.Int).SetBytes(k.Key)
		
		// For secp256k1, the order is 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
		order := new(big.Int).SetBytes([]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
		})
		
		childKeyInt := new(big.Int).Add(ilInt, privKeyInt)
		childKeyInt = childKeyInt.Mod(childKeyInt, order)
		
		// Check if the key is zero
		zero := new(big.Int)
		if childKeyInt.Cmp(zero) == 0 {
			return nil, ErrInvalidKey
		}
		
		// Pad to 32 bytes
		childKey = make([]byte, 32)
		childKeyBytes := childKeyInt.Bytes()
		copy(childKey[32-len(childKeyBytes):], childKeyBytes)
	} else {
		// Public key derivation would go here
		// For simplicity, we're just using the IL part
		childKey = IL
	}

	// Create the child key
	child := &Key{
		Key:               childKey,
		ChainCode:         IR,
		Depth:             k.Depth + 1,
		Index:             index,
		ParentFingerprint: k.Fingerprint(),
		IsPrivate:         k.IsPrivate,
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
	if path[0] == 'm' {
		if len(path) < 2 || path[1] != '/' {
			return nil, ErrInvalidPath
		}
		path = path[2:]
	}
	
	// Split by "/"
	for _, part := range bytes.Split([]byte(path), []byte("/")) {
		parts = append(parts, string(part))
	}

	// Derive each part
	key := k
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}

		var index uint32
		if part[len(part)-1] == '\'' {
			// Hardened key
			_, err := fmt.Sscanf(part[:len(part)-1], "%d", &index)
			if err != nil {
				return nil, ErrInvalidPath
			}
			index += HardenedKeyStart
		} else {
			// Normal key
			_, err := fmt.Sscanf(part, "%d", &index)
			if err != nil {
				return nil, ErrInvalidPath
			}
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
	// testnet: 0x043587CF public, 0x04358394 private
	var version []byte
	if isPublic {
		version = []byte{0x04, 0x88, 0xB2, 0x1E} // xpub
	} else {
		version = []byte{0x04, 0x88, 0xAD, 0xE4} // xprv
	}

	// 1 byte: depth
	depth := []byte{k.Depth}

	// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
	parentFingerprint := k.ParentFingerprint

	// 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
	childIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(childIndex, k.Index)

	// 32 bytes: the chain code
	chainCode := k.ChainCode

	// 33 bytes: the public key or private key data
	// serP(K) for public keys, 0x00 || ser256(k) for private keys
	var keyData []byte
	if isPublic {
		keyData = k.PublicKey()
	} else {
		keyData = make([]byte, 33)
		keyData[0] = 0x00 // Private key prefix
		copy(keyData[1:], k.Key)
	}

	// Concatenate all parts
	raw := append(version, depth...)
	raw = append(raw, parentFingerprint...)
	raw = append(raw, childIndex...)
	raw = append(raw, chainCode...)
	raw = append(raw, keyData...)

	// Base58Check encode
	return base58.CheckEncode(raw, 0) // The '0' is for the version byte, which is already part of 'raw'
}