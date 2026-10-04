// Package sha256 provides a step-by-step SHA-256 learning exercise based on FIPS 180-4.
package sha256

import (
	"hash"
)

const (
	Size      = 32
	Size224   = 28
	BlockSize = 64

	maxMessageBytes = (uint64(1) << 61) - 1
)

// initialState256 comes from FIPS 180-4 §5.3.3. Copy it for each hash computation; do not modify this table.
var initialState256 = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// initialState224 is fixed data from FIPS 180-4 (2015) §5.3.2; copy before use.
var initialState224 = [8]uint32{
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
}

// roundConstants256 comes from FIPS 180-4 §4.2.2 and is provided as fixed data for the exercise.
var roundConstants256 = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

type digest256 struct {
	state      [8]uint32
	buffer     [BlockSize]byte
	buffered   int
	totalbytes uint64
	is224      bool
}

// New returns a new hash.Hash computing the SHA-256 checksum.
func New() hash.Hash {
	return &digest256{
		state: initialState256,
	}
}

// New224 returns a new hash.Hash computing the SHA-224 checksum.
func New224() hash.Hash {
	return &digest256{
		state: initialState224,
		is224: true,
	}
}

func (d *digest256) Write(p []byte) (n int, err error) {
	n = len(p)
	if uint64(n)+d.totalbytes > maxMessageBytes {
		panic("sha256: message length must be less than 2^64 bits (FIPS 180-4 §5.1.1)")
	}
	d.totalbytes += uint64(n)

	for len(p) > 0 {
		nn := copy(d.buffer[d.buffered:], p)
		d.buffered += nn
		if d.buffered == BlockSize {
			compress256(&d.state, d.buffer)
			d.buffered = 0
		}
		p = p[nn:]
	}
	return n, nil
}

func (d *digest256) Sum(in []byte) []byte {
	dCopy := *d
	if dCopy.is224 {
		sum := dCopy.checkSum()
		return append(in, sum[:Size224]...)
	}
	sum := dCopy.checkSum()
	return append(in, sum[:]...)
}

func (d *digest256) checkSum() [Size]byte {
	totalBits := d.totalbytes << 3
	var padded [BlockSize]byte
	copy(padded[:], d.buffer[:d.buffered])
	padded[d.buffered] = 0x80
	if d.buffered%BlockSize < 56 {
		for i := d.buffered + 1; i < 56; i++ {
			padded[i] = 0
		}
	} else {
		for i := d.buffered + 1; i < BlockSize; i++ {
			padded[i] = 0
		}
		compress256(&d.state, padded)
		for i := 0; i < 56; i++ {
			padded[i] = 0
		}
	}
	for i := 0; i < 8; i++ {
		padded[56+i] = byte(totalBits >> (56 - 8*i))
	}
	compress256(&d.state, padded)
	var digest [Size]byte
	for i, s := range d.state {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}
	return digest
}

func (d *digest256) Size() int {
	if d.is224 {
		return Size224
	}
	return Size
}

func (d *digest256) BlockSize() int { return BlockSize }

func (d *digest256) Reset() {
	if d.is224 {
		d.state = initialState224
	} else {
		d.state = initialState256
	}
	d.buffered = 0
	d.totalbytes = 0
}

// Sum256 returns the SHA-256 digest of data without modifying data or its backing array.
// This exercise accepts whole-byte messages only; nil and empty slices represent the same empty message.
// Precondition: the message length in bits is less than 2^64 (FIPS 180-4 §6.2).
func Sum256(data []byte) [Size]byte {
	d := New()
	d.Write(data)
	var sum [Size]byte
	d.Sum(sum[:0])
	return sum
}

// Sum224 returns the SHA-224 digest without modifying data or its backing array.
// FIPS 180-4 (2015) §§5.3.2 and 6.3: use SHA-256 padding and compression with the SHA-224 IV.
// The exercise accepts whole-byte messages whose bit length is less than 2^64.
func Sum224(data []byte) [Size224]byte {
	d := New224()
	d.Write(data)
	var sum [Size224]byte
	d.Sum(sum[:0])
	return sum
}

// schedule256 expands a padded 64-byte block into 64 32-bit message words.
func schedule256(block [64]byte) [64]uint32 {
	var w [64]uint32
	// W[0..15] = M[0..15], decoded in big-endian order.
	for i := 0; i < 16; i++ {
		w[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 | uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
	}
	// W[16..63] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
	for i := 16; i < 64; i++ {
		w[i] = smallSigma1_256(w[i-2]) + w[i-7] + smallSigma0_256(w[i-15]) + w[i-16]
	}
	return w
}

// compress256 processes one block and adds the result to state.
// state must be non-nil. Use a copy of the algorithm-specific IV for the first block and the previous state for subsequent blocks.
func compress256(state *[8]uint32, block [64]byte) {
	w := schedule256(block)
	tmpState := make([]uint32, 8)
	copy(tmpState, state[:])

	for i := 0; i < 64; i++ {
		T1 := tmpState[7] + bigSigma1_256(tmpState[4]) + ch_32(tmpState[4], tmpState[5], tmpState[6]) + roundConstants256[i] + w[i]
		T2 := bigSigma0_256(tmpState[0]) + maj_32(tmpState[0], tmpState[1], tmpState[2])
		tmpState[7] = tmpState[6]
		tmpState[6] = tmpState[5]
		tmpState[5] = tmpState[4]
		tmpState[4] = tmpState[3] + T1
		tmpState[3] = tmpState[2]
		tmpState[2] = tmpState[1]
		tmpState[1] = tmpState[0]
		tmpState[0] = T1 + T2
	}
	for i := 0; i < 8; i++ {
		state[i] += tmpState[i]
	}
}

// σ0_256 = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x)
func smallSigma0_256(x uint32) uint32 {
	return (x>>7 | x<<(32-7)) ^ (x>>18 | x<<(32-18)) ^ (x >> 3)
}

// σ1_256 = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x)
func smallSigma1_256(x uint32) uint32 {
	return (x>>17 | x<<(32-17)) ^ (x>>19 | x<<(32-19)) ^ (x >> 10)
}

// Σ0_256 = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x)
func bigSigma0_256(x uint32) uint32 {
	return (x>>2 | x<<(32-2)) ^ (x>>13 | x<<(32-13)) ^ (x>>22 | x<<(32-22))
}

// Σ1_256 = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x)
func bigSigma1_256(x uint32) uint32 {
	return (x>>6 | x<<(32-6)) ^ (x>>11 | x<<(32-11)) ^ (x>>25 | x<<(32-25))
}

// ch_32 = (x & y) ⊕ (~x & z)
func ch_32(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

// maj_32 = (x & y) ⊕ (x & z) ⊕ (y & z)
func maj_32(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}
