// Package aes implements the AES-128, AES-192, and AES-256 single-block primitives.
// This is a learning implementation, not a production cipher.
package aes

import (
	"crypto/cipher"
	"errors"
)

// blockSize is the AES block size in bytes, for all three key sizes.
const blockSize = 16

// aesCipher holds the key schedule for one key. Construct it with NewCipher.
// Encrypt and Decrypt must keep their working state local and leave these fields unchanged.
type aesCipher struct {
	expanded []byte
	rounds   int
}

var _ cipher.Block = (*aesCipher)(nil)

// NewCipher creates an AES-128, AES-192, or AES-256 block cipher.
// It accepts only 16-, 24-, or 32-byte keys and must not retain the caller's key slice.
// Algorithm: FIPS 197-upd1 (2023), section 5.2.
// API: https://pkg.go.dev/crypto/aes#NewCipher
func NewCipher(key []byte) (cipher.Block, error) {
	// Reuse expandKey, propagate invalid-key errors, and keep its result in aesCipher.
	expanded, rounds, err := expandKey(key)
	if err != nil {
		return nil, err
	}
	return &aesCipher{expanded: expanded, rounds: rounds}, nil
}

// BlockSize returns the AES block size in bytes.
func (c *aesCipher) BlockSize() int {
	return blockSize
}

// Encrypt encrypts src[:blockSize] into dst[:blockSize], leaving the remaining bytes untouched.
// As in Go's crypto/aes, short buffers and inexact overlap of the first blocks must panic.
// Identical starting addresses are allowed for in-place operation.
// Algorithm: FIPS 197-upd1 (2023), section 5.1, Algorithm 1.
// API: https://pkg.go.dev/crypto/cipher#Block
func (c *aesCipher) Encrypt(dst, src []byte) {
	// Validate buffers before writing, copy the input into a local [blockSize]byte,
	// apply CIPHER with c.expanded and c.rounds, then copy the result to dst.
	c.checkBlockBuffers(dst, src)
	var state [blockSize]byte
	copy(state[:], src[:blockSize])
	c.encryptBlock(&state)
	copy(dst[:blockSize], state[:])
}

// Decrypt decrypts src[:blockSize] into dst[:blockSize], leaving the remaining bytes untouched.
// It has the same buffer requirements as Encrypt and uses the same stored key schedule.
// Algorithm: FIPS 197-upd1 (2023), section 5.3, Algorithm 3.
func (c *aesCipher) Decrypt(dst, src []byte) {
	// Apply INVCIPHER with round keys in reverse order. AddRoundKey precedes InvMixColumns.
	c.checkBlockBuffers(dst, src)
	var state [blockSize]byte
	copy(state[:], src[:blockSize])
	c.decryptBlock(&state)
	copy(dst[:blockSize], state[:])
}

func (c *aesCipher) checkBlockBuffers(dst, src []byte) {
	if len(src) < blockSize || len(dst) < blockSize {
		panic("AES: short buffer for cipher.Block operation")
	}
	if &dst[0] == &src[0] {
		// Exact overlap is allowed; only partial overlap is rejected.
		return
	}

	for i := 0; i < blockSize; i++ {
		if &dst[i] == &src[0] || &dst[0] == &src[i] {
			panic("AES: overlapping buffers for cipher.Block operation")
		}
	}
}

func (c *aesCipher) encryptBlock(state *[16]byte) {
	addRoundKey(state, [16]byte(c.expanded[0:16]))
	for round := 1; round < c.rounds; round++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, [16]byte(c.expanded[16*round:16*(round+1)]))
	}
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, [16]byte(c.expanded[16*c.rounds:]))
}

func (c *aesCipher) decryptBlock(state *[16]byte) {
	addRoundKey(state, [16]byte(c.expanded[16*c.rounds:]))
	for round := c.rounds - 1; round > 0; round-- {
		invShiftRows(state)
		invSubBytes(state)
		addRoundKey(state, [16]byte(c.expanded[16*round:16*(round+1)]))
		invMixColumns(state)
	}
	invShiftRows(state)
	invSubBytes(state)
	addRoundKey(state, [16]byte(c.expanded[0:16]))
}

// xtime multiplies a byte by {02} in the AES finite field.
func xtime(value byte) byte {
	if value&0x80 == 0 {
		return value << 1
	}
	return (value << 1) ^ 0x1b
}

// All state helpers use column-major storage: state[r+4*c] is row r, column c.
func subBytes(state *[16]byte) {
	for i := range state {
		state[i] = sbox0[state[i]]
	}
}

func shiftRows(state *[16]byte) {
	for r := 1; r < 4; r++ {
		row := [4]byte{}
		for c := 0; c < 4; c++ {
			row[c] = state[r+4*c]
		}
		for c := 0; c < 4; c++ {
			state[r+4*c] = row[(c+r)%4]
		}
	}
}

func mixColumns(state *[16]byte) {
	for c := 0; c < 4; c++ {
		a := [4]byte{}
		for r := 0; r < 4; r++ {
			a[r] = state[r+4*c]
		}
		state[0+4*c] = xtime(a[0]) ^ xtime(a[1]) ^ a[1] ^ a[2] ^ a[3]
		state[1+4*c] = a[0] ^ xtime(a[1]) ^ xtime(a[2]) ^ a[2] ^ a[3]
		state[2+4*c] = a[0] ^ a[1] ^ xtime(a[2]) ^ xtime(a[3]) ^ a[3]
		state[3+4*c] = xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xtime(a[3])
	}
}

func addRoundKey(state *[16]byte, roundKey [16]byte) {
	for i := range state {
		state[i] ^= roundKey[i]
	}
}

// expandKey expands a 16-, 24-, or 32-byte key into a full AES key schedule.
// Returns the expanded key, the number of rounds, and an error if the input
// key length is invalid. The expanded key is 4*(Nr+1)*4 bytes long.
func expandKey(key []byte) (expanded []byte, rounds int, err error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, 0, errors.New("AES: invalid key length")
	}

	nk := len(key) / 4
	nr := nk + 6
	expanded = make([]byte, 4*(nr+1)*4)
	copy(expanded, key)

	rcon := [10]byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}
	for i := nk; i < 4*(nr+1); i++ {
		t := expanded[4*(i-1) : 4*i]
		if i%nk == 0 {
			t = []byte{
				sbox0[t[1]] ^ rcon[i/nk-1],
				sbox0[t[2]],
				sbox0[t[3]],
				sbox0[t[0]],
			}
		} else if nk > 6 && i%nk == 4 {
			t = []byte{
				sbox0[t[0]],
				sbox0[t[1]],
				sbox0[t[2]],
				sbox0[t[3]],
			}
		}
		for j := 0; j < 4; j++ {
			expanded[4*i+j] = expanded[4*(i-nk)+j] ^ t[j]
		}
	}

	return expanded, nr, nil
}

func invSubBytes(state *[16]byte) {
	for i := range state {
		state[i] = sbox1[state[i]]
	}
}

func invShiftRows(state *[16]byte) {
	for r := 1; r < 4; r++ {
		row := [4]byte{}
		for c := 0; c < 4; c++ {
			row[c] = state[r+4*c]
		}
		for c := 0; c < 4; c++ {
			state[r+4*c] = row[(c-r+4)%4]
		}
	}
}

func invMixColumns(state *[16]byte) {
	for c := 0; c < 4; c++ {
		a := [4]byte{}
		for r := 0; r < 4; r++ {
			a[r] = state[r+4*c]
		}
		t := xtime(xtime(xtime(a[0] ^ a[1] ^ a[2] ^ a[3])))
		state[0+4*c] = t ^ xtime(xtime(a[0]^a[2])) ^ xtime(a[0]^a[1]) ^ a[1] ^ a[2] ^ a[3]
		state[1+4*c] = t ^ xtime(xtime(a[1]^a[3])) ^ xtime(a[1]^a[2]) ^ a[0] ^ a[2] ^ a[3]
		state[2+4*c] = t ^ xtime(xtime(a[0]^a[2])) ^ xtime(a[2]^a[3]) ^ a[0] ^ a[1] ^ a[3]
		state[3+4*c] = t ^ xtime(xtime(a[1]^a[3])) ^ xtime(a[3]^a[0]) ^ a[0] ^ a[1] ^ a[2]
	}
}
