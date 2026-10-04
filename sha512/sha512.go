// Package sha512 provides a SHA-512 learning exercise based on FIPS 180-4 (2015).
package sha512

import "hash"

const (
	size384     = 48
	size512     = 64
	size512_224 = 28
	size512_256 = 32
	blockSize   = 128

	maxMessageBytesHigh = (uint64(1) << 61) - 1
)

// initialState384 is fixed data from FIPS 180-4 (2015) §5.3.4; copy before use.
var initialState384 = [8]uint64{
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
	0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511,
	0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
}

// initialState512 is fixed data from FIPS 180-4 (2015) §5.3.5; copy before use.
var initialState512 = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// initialState512_224 is fixed data from FIPS 180-4 (2015) §5.3.6.1; copy before use.
var initialState512_224 = [8]uint64{
	0x8c3d37c819544da2, 0x73e1996689dcd4d6,
	0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
	0x0f6d2b697bd44da8, 0x77e36f7304c48942,
	0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1,
}

// initialState512_256 is fixed data from FIPS 180-4 (2015) §5.3.6.2; copy before use.
var initialState512_256 = [8]uint64{
	0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
	0x2393b86b6f53b151, 0x963877195940eabd,
	0x96283ee2a88effe3, 0xbe5e1e2553863992,
	0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
}

// roundConstants512 is fixed data from FIPS 180-4 (2015) §4.2.3.
var roundConstants512 = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

type digest512 struct {
	state          [8]uint64
	buffer         [blockSize]byte
	buffered       int
	totalBytesHigh uint64
	totalBytesLow  uint64
	size           int // 64 for SHA-512, 48 for SHA-384, 32 for SHA-512/256, 28 for SHA-512/224
}

// New384 returns a new hash.Hash computing the SHA-384 checksum.
func New384() hash.Hash {
	return &digest512{
		state: initialState384,
		size:  size384,
	}
}

// New returns a new hash.Hash computing the SHA-512 checksum.
func New() hash.Hash {
	return &digest512{
		state: initialState512,
		size:  size512,
	}
}

// New512_224 returns a new hash.Hash computing the SHA-512/224 checksum.
func New512_224() hash.Hash {
	return &digest512{
		state: initialState512_224,
		size:  size512_224,
	}
}

// New512_256 returns a new hash.Hash computing the SHA-512/256 checksum.
func New512_256() hash.Hash {
	return &digest512{
		state: initialState512_256,
		size:  size512_256,
	}
}

func (d *digest512) Write(p []byte) (n int, err error) {
	n = len(p)
	low := d.totalBytesLow + uint64(n)
	high := d.totalBytesHigh
	if low < d.totalBytesLow {
		high++
	}
	if high > maxMessageBytesHigh {
		panic("sha512: message length must be less than 2^128 bits (FIPS 180-4 §5.1.2)")
	}
	d.totalBytesHigh = high
	d.totalBytesLow = low

	for len(p) > 0 {
		nn := copy(d.buffer[d.buffered:], p)
		d.buffered += nn
		if d.buffered == blockSize {
			compress512(&d.state, d.buffer)
			d.buffered = 0
		}
		p = p[nn:]
	}
	return n, nil
}

func (d *digest512) Sum(in []byte) []byte {
	dCopy := *d
	sum := dCopy.checkSum()
	return append(in, sum[:dCopy.size]...)
}

func (d *digest512) checkSum() [size512]byte {
	totalBitsHigh := d.totalBytesHigh<<3 | d.totalBytesLow>>61
	totalBitsLow := d.totalBytesLow << 3
	var padded [blockSize]byte
	copy(padded[:], d.buffer[:d.buffered])
	padded[d.buffered] = 0x80
	if d.buffered%blockSize < 112 {
		for i := d.buffered + 1; i < 112; i++ {
			padded[i] = 0
		}
	} else {
		for i := d.buffered + 1; i < blockSize; i++ {
			padded[i] = 0
		}
		compress512(&d.state, padded)
		for i := 0; i < 112; i++ {
			padded[i] = 0
		}
	}
	for i := 0; i < 8; i++ {
		padded[112+i] = byte(totalBitsHigh >> (56 - 8*i))
		padded[120+i] = byte(totalBitsLow >> (56 - 8*i))
	}
	compress512(&d.state, padded)
	var digest [size512]byte
	for i, s := range d.state {
		digest[i*8] = byte(s >> 56)
		digest[i*8+1] = byte(s >> 48)
		digest[i*8+2] = byte(s >> 40)
		digest[i*8+3] = byte(s >> 32)
		digest[i*8+4] = byte(s >> 24)
		digest[i*8+5] = byte(s >> 16)
		digest[i*8+6] = byte(s >> 8)
		digest[i*8+7] = byte(s)
	}
	return digest
}

func (d *digest512) Reset() {
	switch d.size {
	case size512:
		copy(d.state[:], initialState512[:])
	case size384:
		copy(d.state[:], initialState384[:])
	case size512_224:
		copy(d.state[:], initialState512_224[:])
	case size512_256:
		copy(d.state[:], initialState512_256[:])
	default:
		panic("sha512: invalid size")
	}
	d.buffered = 0
	d.totalBytesHigh = 0
	d.totalBytesLow = 0
}

func (d *digest512) Size() int {
	return d.size
}

func (d *digest512) BlockSize() int {
	return blockSize
}

// All public functions accept whole-byte messages and preserve the input and its backing array.
// The standard permits bit lengths below 2^128; this one-shot API is limited by Go slice sizes.
// nil and empty inputs are equivalent. Copy each variant's IV before processing blocks.

// Sum384 returns the SHA-384 digest; see FIPS 180-4 (2015) §§5.3.4 and 6.5.
func Sum384(data []byte) [48]byte {
	d := New384()
	d.Write(data)
	var sum [size384]byte
	d.Sum(sum[:0])
	return sum
}

// Sum512 returns the SHA-512 digest; see FIPS 180-4 (2015) §§5.3.5 and 6.4.
func Sum512(data []byte) [64]byte {
	d := New()
	d.Write(data)
	var sum [size512]byte
	d.Sum(sum[:0])
	return sum
}

// Sum512_224 returns the SHA-512/224 digest; see FIPS 180-4 (2015) §§5.3.6.1 and 6.6.
func Sum512_224(data []byte) [28]byte {
	d := New512_224()
	d.Write(data)
	var sum [size512_224]byte
	d.Sum(sum[:0])
	return sum
}

// Sum512_256 returns the SHA-512/256 digest; see FIPS 180-4 (2015) §§5.3.6.2 and 6.7.
func Sum512_256(data []byte) [32]byte {
	d := New512_256()
	d.Write(data)
	var sum [size512_256]byte
	d.Sum(sum[:0])
	return sum
}

// schedule512 follows FIPS 180-4 (2015) §§4.1.3, 5.2.2, and 6.4.2, step 1.
func schedule512(block [128]byte) [80]uint64 {
	var w [80]uint64
	// W[0..15] = M[0..15], decoded in big-endian order.
	for i := 0; i < 16; i++ {
		w[i] = uint64(block[i*8])<<56 | uint64(block[i*8+1])<<48 | uint64(block[i*8+2])<<40 | uint64(block[i*8+3])<<32 |
			uint64(block[i*8+4])<<24 | uint64(block[i*8+5])<<16 | uint64(block[i*8+6])<<8 | uint64(block[i*8+7])
	}
	// W[16..79] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
	for i := 16; i < 80; i++ {
		w[i] = smallSigma1_512(w[i-2]) + w[i-7] + smallSigma0_512(w[i-15]) + w[i-16]
	}
	return w
}

// Compress512 follows FIPS 180-4 (2015) §§4.1.3, 4.2.3, and 6.4.2, steps 2-4.
// state must be non-nil; all four variants use this same compression function.
func compress512(state *[8]uint64, block [128]byte) {
	w := schedule512(block)
	tmpState := make([]uint64, 8)
	copy(tmpState, state[:])

	for i := 0; i < 80; i++ {
		t1 := tmpState[7] + bigSigma1_512(tmpState[4]) + ch_64(tmpState[4], tmpState[5], tmpState[6]) + roundConstants512[i] + w[i]
		t2 := bigSigma0_512(tmpState[0]) + maj_64(tmpState[0], tmpState[1], tmpState[2])
		tmpState[7] = tmpState[6]
		tmpState[6] = tmpState[5]
		tmpState[5] = tmpState[4]
		tmpState[4] = tmpState[3] + t1
		tmpState[3] = tmpState[2]
		tmpState[2] = tmpState[1]
		tmpState[1] = tmpState[0]
		tmpState[0] = t1 + t2
	}
	for i := 0; i < 8; i++ {
		state[i] += tmpState[i]
	}
}

// σ0_512 = ROTR^1(x) ⊕ ROTR^8(x) ⊕ SHR^7(x)
func smallSigma0_512(x uint64) uint64 {
	return (x>>1 | x<<(64-1)) ^ (x>>8 | x<<(64-8)) ^ (x >> 7)
}

// σ1_512 = ROTR^19(x) ⊕ ROTR^61(x) ⊕ SHR^6(x)
func smallSigma1_512(x uint64) uint64 {
	return (x>>19 | x<<(64-19)) ^ (x>>61 | x<<(64-61)) ^ (x >> 6)
}

// Σ0_512 = ROTR^28(x) ⊕ ROTR^34(x) ⊕ ROTR^39(x)
func bigSigma0_512(x uint64) uint64 {
	return (x>>28 | x<<36) ^ (x>>34 | x<<30) ^ (x>>39 | x<<25)
}

// Σ1_512 = ROTR^14(x) ⊕ ROTR^18(x) ⊕ ROTR^41(x)
func bigSigma1_512(x uint64) uint64 {
	return (x>>14 | x<<50) ^ (x>>18 | x<<46) ^ (x>>41 | x<<23)
}

// ch_64 = (x & y) ⊕ (~x & z)
func ch_64(x, y, z uint64) uint64 {
	return (x & y) ^ (^x & z)
}

// maj_64 = (x & y) ⊕ (x & z) ⊕ (y & z)
func maj_64(x, y, z uint64) uint64 {
	return (x & y) ^ (x & z) ^ (y & z)
}
