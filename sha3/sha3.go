// Package sha3 provides SHA-3 hash.Hash and SHAKE hash.XOF exercises.
// Specification: FIPS 202 (August 2015), sections 3-6 and Appendix B.
// Algorithms remain TODOs; see ../docs/fips202.md for the implementation order.
package sha3

import "hash"

const (
	// Digest sizes are in bytes.
	Size224 = 28
	Size256 = 32
	Size384 = 48
	Size512 = 64

	// Block sizes are the sponge rates in bytes.
	BlockSize224 = 144
	BlockSize256 = 136
	BlockSize384 = 104
	BlockSize512 = 72
)

// digest implements the fixed-output hash interface, like digest256/digest512.
// Its sponge remains in the absorbing phase when Sum computes a snapshot.
type digest struct {
	sponge spongeState
	size   int
}

var _ hash.Hash = (*digest)(nil)

// New224 returns a hash.Hash computing SHA3-224.
func New224() hash.Hash {
	return &digest{sponge: newSponge(BlockSize224, suffixSHA3), size: Size224}
}

// New256 returns a hash.Hash computing SHA3-256.
func New256() hash.Hash {
	return &digest{sponge: newSponge(BlockSize256, suffixSHA3), size: Size256}
}

// New384 returns a hash.Hash computing SHA3-384.
func New384() hash.Hash {
	return &digest{sponge: newSponge(BlockSize384, suffixSHA3), size: Size384}
}

// New512 returns a hash.Hash computing SHA3-512.
func New512() hash.Hash {
	return &digest{sponge: newSponge(BlockSize512, suffixSHA3), size: Size512}
}

// Write absorbs p and returns len(p), nil. It must not retain p.
func (d *digest) Write(p []byte) (int, error) { return d.sponge.write(p) }

// Sum appends the digest to b without changing the running hash.
// The prefix b must be preserved. Further Write and Sum calls remain valid.
func (d *digest) Sum(b []byte) []byte {
	panic(todo("TODO K-07: copy the sponge, squeeze size bytes, append to b without changing the original; FIPS 202 section 6.1 and hash.Hash"))
}

// Reset discards all input and restores this variant's initial state.
func (d *digest) Reset()         { d.sponge.reset() }
func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return d.sponge.rate }

// Sum224 returns the SHA3-224 digest of data without modifying it.
func Sum224(data []byte) [Size224]byte {
	h := New224()
	h.Write(data)
	var out [Size224]byte
	copy(out[:], h.Sum(out[:0]))
	return out
}

// Sum256 returns the SHA3-256 digest of data without modifying it.
func Sum256(data []byte) [Size256]byte {
	h := New256()
	h.Write(data)
	var out [Size256]byte
	copy(out[:], h.Sum(out[:0]))
	return out
}

// Sum384 returns the SHA3-384 digest of data without modifying it.
func Sum384(data []byte) [Size384]byte {
	h := New384()
	h.Write(data)
	var out [Size384]byte
	copy(out[:], h.Sum(out[:0]))
	return out
}

// Sum512 returns the SHA3-512 digest of data without modifying it.
func Sum512(data []byte) [Size512]byte {
	h := New512()
	h.Write(data)
	var out [Size512]byte
	copy(out[:], h.Sum(out[:0]))
	return out
}
