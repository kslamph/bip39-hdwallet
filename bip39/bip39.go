// Package bip39 implements the BIP39 specification for mnemonic codes.
package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// ErrInvalidMnemonic is returned when trying to decode an invalid mnemonic.
	ErrInvalidMnemonic = errors.New("bip39: invalid mnemonic")

	// ErrEntropyLength is returned when trying to generate a mnemonic with invalid entropy length.
	ErrEntropyLength = errors.New("bip39: entropy length must be [128, 256] and a multiple of 32")

	// ErrMnemonicLength is returned when trying to generate a seed from a mnemonic with an invalid number of words.
	ErrMnemonicLength = errors.New("bip39: mnemonic must be 12, 15, 18, 21 or 24 words")
)

// getBits extracts n bits from a buffer at a given bit offset
func getBits(buf []byte, offset, n int) uint32 {
	if n > 32 {
		panic("getBits can't extract more than 32 bits")
	}

	byteOffset := offset / 8
	bitOffset := offset % 8

	var result uint32
	// Read up to 4 bytes to get enough bits
	for i := 0; i < 4 && byteOffset+i < len(buf); i++ {
		result |= uint32(buf[byteOffset+i]) << uint(8*i)
	}

	// Shift right to align the desired bits to the right
	result >>= uint(bitOffset)

	// Mask to keep only the desired number of bits
	mask := uint32(1<<uint(n)) - 1
	result &= mask

	return result
}

// indicesToBytes converts 11-bit word indices back to a byte array
func indicesToBytes(indices []int, bits int) []byte {
	buf := make([]byte, (bits+7)/8)
	
	for i, index := range indices {
		// For each word, set 11 bits in the bit buffer
		for j := 0; j < 11; j++ {
			// Check if bit j of index is set (bit 10 is MSB)
			bitSet := (index & (1 << (10 - j))) != 0
			
			// Calculate position in bit buffer
			bitPos := i*11 + j
			bytePos := bitPos / 8
			bitOffset := 7 - (bitPos % 8) // Bit 0 is MSB in byte
			
			// Set the bit if needed
			if bitSet && bytePos < len(buf) {
				buf[bytePos] |= (1 << bitOffset)
			}
		}
	}
	
	return buf
}

// NewEntropy generates a new entropy byte slice with the given bit size.
// bitSize must be in [128, 256] and a multiple of 32.
func NewEntropy(bitSize int) ([]byte, error) {
	if bitSize < 128 || bitSize > 256 || bitSize%32 != 0 {
		return nil, ErrEntropyLength
	}

	entropy := make([]byte, bitSize/8)
	_, err := rand.Read(entropy)
	if err != nil {
		return nil, err
	}

	return entropy, nil
}

// NewMnemonic generates a new mnemonic from the given entropy.
func NewMnemonic(entropy []byte) (string, error) {
	// We only support 128-256 bits of entropy
	entropyBitLength := len(entropy) * 8
	if entropyBitLength < 128 || entropyBitLength > 256 || entropyBitLength%32 != 0 {
		return "", ErrEntropyLength
	}

	// Calculate the checksum by taking the first ENT / 32 bits of the SHA256 hash
	// where ENT is the entropy length in bits
	hash := sha256.Sum256(entropy)
	checksumBitLength := uint(entropyBitLength / 32)

	// Create a buffer with entropy + checksum
	entropyWithChecksumBitLen := entropyBitLength + int(checksumBitLength)
	entropyWithChecksumByteLen := (entropyWithChecksumBitLen + 7) / 8
	buf := make([]byte, entropyWithChecksumByteLen)
	copy(buf, entropy)
	
	// Add the checksum bits to the end
	checksumByte := hash[0]
	for i := 0; i < int(checksumBitLength); i++ {
		// Get bit i from checksumByte
		bit := (checksumByte >> (7 - i)) & 1
		
		// Set bit in buf at position entropyBitLength + i
		bytePos := (entropyBitLength + i) / 8
		bitPos := (entropyBitLength + i) % 8
		if bit == 1 {
			buf[bytePos] |= 1 << (7 - bitPos)
		}
	}

	// Calculate the number of words needed
	wordCount := entropyWithChecksumBitLen / 11
	
	// Generate the mnemonic words
	words := make([]string, wordCount)
	for i := 0; i < wordCount; i++ {
		// Extract the 11-bit word index
		wordIdx := getBits(buf, i*11, 11)
		
		// Convert to word
		if int(wordIdx) >= len(Wordlist) {
			return "", ErrInvalidMnemonic
		}
		words[i] = Wordlist[wordIdx]
	}
	
	return strings.Join(words, " "), nil
}

// MnemonicToByteArray converts a mnemonic to its byte representation.
func MnemonicToByteArray(mnemonic string) ([]byte, error) {
	words := strings.Fields(mnemonic)
	wordsLength := len(words)
	
	// Validate word count
	if wordsLength < 12 || wordsLength > 24 || wordsLength%3 != 0 {
		return nil, ErrMnemonicLength
	}

	// Convert words to indices
	indices := make([]int, wordsLength)
	for i, word := range words {
		index, ok := Wordmap[word]
		if !ok {
			return nil, fmt.Errorf("%w: word `%s` not in wordlist", ErrInvalidMnemonic, word)
		}
		indices[i] = index
	}

	// Calculate entropy and checksum sizes
	entropyBitLength := wordsLength * 11 * 32 / 33
	checksumBitLength := wordsLength * 11 / 33
	entropyByteLength := entropyBitLength / 8

	// Reconstruct the bit buffer
	totalBits := wordsLength * 11
	buf := indicesToBytes(indices, totalBits)
	
	// Extract entropy bytes
	entropy := make([]byte, entropyByteLength)
	copy(entropy, buf[:entropyByteLength])
	
	// Extract checksum bits
	var checksumByte byte
	if entropyByteLength < len(buf) {
		checksumByte = buf[entropyByteLength]
	}

	// Calculate the expected checksum
	hash := sha256.Sum256(entropy)
	expectedChecksum := hash[0] >> (8 - checksumBitLength)

	// Extract the actual checksum bits
	actualChecksum := checksumByte >> (8 - checksumBitLength)

	// Verify the checksum
	if actualChecksum != expectedChecksum {
		return nil, ErrInvalidMnemonic
	}

	return entropy, nil
}

// NewSeed generates a new seed from the given mnemonic and passphrase.
// The passphrase can be empty.
func NewSeed(mnemonic, passphrase string) []byte {
	salt := "mnemonic" + passphrase
	seed := pbkdf2.Key([]byte(mnemonic), []byte(salt), 2048, 64, sha256.New)
	return seed
}

// IsMnemonicValid checks if a mnemonic is valid.
func IsMnemonicValid(mnemonic string) bool {
	_, err := MnemonicToByteArray(mnemonic)
	return err == nil
}