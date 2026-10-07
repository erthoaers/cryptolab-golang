package sha3

import "hash"

// SHAKE block sizes are sponge rates in bytes, not output lengths.
const (
	BlockSizeSHAKE128 = 168
	BlockSizeSHAKE256 = 136
)

// shake exposes absorption followed by a continuous output stream.
// Unlike digest.Sum, Read advances this instance's state.
type shake struct {
	sponge spongeState
}

var _ hash.XOF = (*shake)(nil)

// NewSHAKE128 returns a SHAKE128 XOF.
func NewSHAKE128() hash.XOF {
	return &shake{sponge: newSponge(BlockSizeSHAKE128, suffixSHAKE)}
}

// NewSHAKE256 returns a SHAKE256 XOF.
func NewSHAKE256() hash.XOF {
	return &shake{sponge: newSponge(BlockSizeSHAKE256, suffixSHAKE)}
}

// Write absorbs p and returns len(p), nil. It panics after any Read, including
// a zero-length Read. Reset permits writing again. It must not retain p.
func (x *shake) Write(p []byte) (int, error) { return x.sponge.write(p) }

// Read fills p with the next output bytes and returns len(p), nil, never EOF.
// Even Read(nil) enters the squeezing phase, matching Go 1.27.1 crypto/sha3.
func (x *shake) Read(p []byte) (int, error) { return x.sponge.read(p) }

// Reset discards all absorbed input and unread output, retaining the variant.
func (x *shake) Reset()         { x.sponge.reset() }
func (x *shake) BlockSize() int { return x.sponge.rate }

// SumSHAKE128 returns outputLen bytes of SHAKE128(data), without modifying data.
// Zero length is valid; a negative outputLen panics.
func SumSHAKE128(data []byte, outputLen int) []byte {
	return sumSHAKE(NewSHAKE128(), data, outputLen)
}

// SumSHAKE256 returns outputLen bytes of SHAKE256(data), without modifying data.
// Zero length is valid; a negative outputLen panics.
func SumSHAKE256(data []byte, outputLen int) []byte {
	return sumSHAKE(NewSHAKE256(), data, outputLen)
}

func sumSHAKE(x hash.XOF, data []byte, outputLen int) []byte {
	if outputLen < 0 {
		panic("sha3: negative output length")
	}
	x.Write(data)
	out := make([]byte, outputLen)
	x.Read(out)
	return out
}
