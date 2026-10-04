// Package sha3 provides the four SHA-3 hashes and two SHAKE XOF exercises.
// Specification: FIPS 202 (August 2015), sections 6.1 and 6.2.
// Shared algorithm TODOs are in keccak.go; see ../docs/fips202.md.
package sha3

const (
	// Size224 is the fixed digest length in bytes.
	Size224 = 28
	// BlockSize224 is the sponge rate in bytes.
	BlockSize224 = 144
)

// Sum224 returns the SHA3-224 digest of data without modifying it.
// This wrapper fixes the parameters; the shared sponge is a TODO.
func Sum224(data []byte) [Size224]byte {
	var out [Size224]byte
	copy(out[:], sponge(data, BlockSize224, 0x06, Size224))
	return out
}

const (
	// Size256 is the fixed digest length in bytes.
	Size256 = 32
	// BlockSize256 is the sponge rate in bytes.
	BlockSize256 = 136
)

// Sum256 returns the SHA3-256 digest of data without modifying it.
// This wrapper fixes the parameters; the shared sponge is a TODO.
func Sum256(data []byte) [Size256]byte {
	var out [Size256]byte
	copy(out[:], sponge(data, BlockSize256, 0x06, Size256))
	return out
}

const (
	// Size384 is the fixed digest length in bytes.
	Size384 = 48
	// BlockSize384 is the sponge rate in bytes.
	BlockSize384 = 104
)

// Sum384 returns the SHA3-384 digest of data without modifying it.
// This wrapper fixes the parameters; the shared sponge is a TODO.
func Sum384(data []byte) [Size384]byte {
	var out [Size384]byte
	copy(out[:], sponge(data, BlockSize384, 0x06, Size384))
	return out
}

const (
	// Size512 is the fixed digest length in bytes.
	Size512 = 64
	// BlockSize512 is the sponge rate in bytes.
	BlockSize512 = 72
)

// Sum512 returns the SHA3-512 digest of data without modifying it.
// This wrapper fixes the parameters; the shared sponge is a TODO.
func Sum512(data []byte) [Size512]byte {
	var out [Size512]byte
	copy(out[:], sponge(data, BlockSize512, 0x06, Size512))
	return out
}

// BlockSizeSHAKE128 is the sponge rate in bytes, not the output length.
const BlockSizeSHAKE128 = 168

// SumSHAKE128 returns outputLen bytes of SHAKE128(data). Zero length is valid;
// negative outputLen must panic. It does not modify or retain data.
// Output storage is independent across calls. The shared sponge is a TODO.
func SumSHAKE128(data []byte, outputLen int) []byte {
	return sponge(data, BlockSizeSHAKE128, 0x1f, outputLen)
}

// BlockSizeSHAKE256 is the sponge rate in bytes, not the output length.
const BlockSizeSHAKE256 = 136

// SumSHAKE256 returns outputLen bytes of SHAKE256(data). Zero length is valid;
// negative outputLen must panic. It does not modify or retain data.
// Output storage is independent across calls. The shared sponge is a TODO.
func SumSHAKE256(data []byte, outputLen int) []byte {
	return sponge(data, BlockSizeSHAKE256, 0x1f, outputLen)
}
