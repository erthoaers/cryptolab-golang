// Package sha1 provides a SHA-1 learning exercise based on FIPS 180-4 (2015).
// SHA-1 is included for historical study, not for new security designs.
package sha1

const (
	size      = 20
	blockSize = 64

	maxMessageBytes = (uint64(1) << 61) - 1
)

// initialState is fixed data from FIPS 180-4 (2015) §5.3.1; copy before use.
var initialState = [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}

// roundConstants is fixed data from FIPS 180-4 (2015) §4.2.1, one entry per 20 rounds.
var roundConstants = [4]uint32{0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6}

type digest struct {
	state      [5]uint32
	buffer     [blockSize]byte
	buffered   int
	totalbytes uint64
}

func New() *digest {
	return &digest{state: initialState}
}

func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	if uint64(n)+d.totalbytes > maxMessageBytes {
		panic("sha1: message length must be less than 2^64 bits (FIPS 180-4 §5.1.1)")
	}
	d.totalbytes += uint64(n)

	for len(p) > 0 {
		nn := copy(d.buffer[d.buffered:], p)
		d.buffered += nn
		if d.buffered == blockSize {
			compress(&d.state, d.buffer)
			d.buffered = 0
		}
		p = p[nn:]
	}
	return n, nil
}

func (d *digest) Sum(in []byte) []byte {
	dCopy := *d
	sum := dCopy.checkSum()
	return append(in, sum[:]...)
}

func (d *digest) checkSum() [size]byte {
	totalBits := d.totalbytes << 3
	var padded [blockSize]byte
	copy(padded[:], d.buffer[:d.buffered])
	padded[d.buffered] = 0x80
	if d.buffered%blockSize < 56 {
		for i := d.buffered + 1; i < 56; i++ {
			padded[i] = 0
		}
	} else {
		for i := d.buffered + 1; i < blockSize; i++ {
			padded[i] = 0
		}
		compress(&d.state, padded)
		for i := 0; i < 56; i++ {
			padded[i] = 0
		}
	}
	for i := 0; i < 8; i++ {
		padded[56+i] = byte(totalBits >> (56 - 8*i))
	}
	compress(&d.state, padded)
	var digest [size]byte
	for i, s := range d.state {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}
	return digest
}

func (d *digest) Reset() {
	d.state = initialState
	d.buffered = 0
	d.totalbytes = 0
}

func (d *digest) Size() int      { return size }
func (d *digest) BlockSize() int { return blockSize }

// Sum returns the SHA-1 digest without modifying data or its backing array.
// This exercise accepts whole-byte messages whose bit length is less than 2^64.
// Follow FIPS 180-4 (2015) §§5.3.1 and 6.1.2; nil and empty inputs are equivalent.
func Sum(data []byte) [20]byte {
	d := New()
	d.Write(data)
	var sum [size]byte
	d.Sum(sum[:0])
	return sum
}

// schedule follows FIPS 180-4 (2015) §§5.2.1 and 6.1.2, step 1.
func schedule(block [64]byte) [80]uint32 {
	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 | uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
	}
	for i := 16; i < 80; i++ {
		w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
		w[i] = (w[i] << 1) | (w[i] >> 31)
	}
	return w
}

// compress follows FIPS 180-4 (2015) §§4.1.1, 4.2.1, and 6.1.2, steps 2-4.
// state must be non-nil; add the final working variables to the incoming state.
func compress(state *[5]uint32, block [64]byte) {
	w := schedule(block)
	tmpState := make([]uint32, 5)
	copy(tmpState, state[:])

	for i := 0; i < 80; i++ {
		t := (tmpState[0]<<5 | tmpState[0]>>(32-5)) + f_t(i, tmpState[1], tmpState[2], tmpState[3]) + tmpState[4] + roundConstants[i/20] + w[i]
		tmpState[4] = tmpState[3]
		tmpState[3] = tmpState[2]
		tmpState[2] = tmpState[1]<<30 | tmpState[1]>>(32-30)
		tmpState[1] = tmpState[0]
		tmpState[0] = t
	}
	for i := 0; i < 5; i++ {
		state[i] += tmpState[i]
	}
}

func f_t(t int, b, c, d uint32) uint32 {
	switch {
	case t < 20:
		// f_t = Ch(a, b, c) = (b & c) ⊕ (~b & d) when 0 ≤ t ≤ 19
		return (b & c) | (^b & d)
	case t < 40:
		// f_t = b ⊕ c ⊕ d when 20 ≤ t ≤ 39
		return b ^ c ^ d
	case t < 60:
		// f_t = Maj(a, b, c) = (b & c) ⊕ (b & d) ⊕ (c & d) when 40 ≤ t ≤ 59
		return (b & c) | (b & d) | (c & d)
	default:
		// f_t = b ⊕ c ⊕ d when 60 ≤ t ≤ 79
		return b ^ c ^ d
	}
}
