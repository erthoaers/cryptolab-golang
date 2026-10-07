package sha3

const (
	suffixSHA3  byte = 0x06 // FIPS 202 section 6.1; includes the first padding bit.
	suffixSHAKE byte = 0x1f // FIPS 202 section 6.2; includes the first padding bit.
	maxRate          = BlockSizeSHAKE128
)

// spongeState owns all storage needed by a stream. Keeping arrays rather than
// slices makes a value copy independent, which is useful for digest.Sum.
type spongeState struct {
	lanes state

	// Before squeezing, buffer[:offset] is the unabsorbed tail.
	// During squeezing, buffer[offset:rate] is the unread output block.
	buffer    [maxRate]byte
	offset    int
	rate      int
	suffix    byte
	squeezing bool
}

func newSponge(rate int, suffix byte) spongeState {
	switch rate {
	case BlockSize512, BlockSize384, BlockSize256, BlockSize224, BlockSizeSHAKE128:
	default:
		panic("sha3: unsupported rate")
	}
	if suffix != suffixSHA3 && suffix != suffixSHAKE {
		panic("sha3: unsupported domain suffix")
	}
	return spongeState{rate: rate, suffix: suffix}
}

// reset preserves the configuration and clears the lanes, buffer and phase.
func (s *spongeState) reset() {
	*s = spongeState{rate: s.rate, suffix: s.suffix}
}

// write absorbs full blocks and saves the unfinished tail in owned storage.
// Return len(p), nil, including for nil or empty writes while absorbing.
// Panic on every write after read. Auxiliary memory must stay bounded.
// FIPS 202 section 4, Algorithm 8, steps 1-6; hash.Hash and hash.XOF contracts.
func (s *spongeState) write(p []byte) (int, error) {
	panic(todo("TODO K-05: absorb streaming writes, retain only the tail, reject Write after Read; FIPS 202 section 4 and hash.XOF"))
}

// read pads and absorbs the final block once, then advances the output cursor.
// A zero-length first read still finalizes input. Repeated reads concatenate
// into a single output stream. Fill out completely, return len(out), nil,
// and never modify storage outside out or retain the caller's output slice.
// FIPS 202 section 4, Algorithm 8, steps 7-10; sections 5.1, 6.2 and Appendix A.2.
func (s *spongeState) read(out []byte) (int, error) {
	panic(todo("TODO K-06: finalize once and squeeze across read boundaries; FIPS 202 sections 4-6 and hash.XOF"))
}

// sponge keeps the original low-level integration tests on the same streaming
// engine used by the public interfaces. It is not a separate algorithm.
func sponge(data []byte, rate int, suffix byte, outputLen int) []byte {
	if outputLen < 0 {
		panic("sha3: negative output length")
	}
	s := newSponge(rate, suffix)
	s.write(data)
	out := make([]byte, outputLen)
	s.read(out)
	return out
}
