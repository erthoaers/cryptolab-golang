// Keccak exercises shared by the six FIPS 202 (August 2015) functions.
// It supports byte-aligned messages and outputs with Keccak-p[1600,24].
// See ../docs/fips202.md. Algorithm bodies deliberately remain TODOs.
package sha3

// todo identifies an unfinished exercise. Tests must fail, never skip it.
type todo string

// state stores lane (x,y) at x+5*y; bit z is bit z of the uint64.
// Byte serialization is little-endian within each lane (sections 3.1, B.1).
type state [25]uint64

// decodeState converts all 200 bytes without changing the input.
func decodeState(in [200]byte) state {
	panic(todo("TODO K-01: decode 25 little-endian lanes; FIPS 202 section 3.1.2"))
}

// encodeState returns all 200 bytes in the inverse order of decodeState.
func encodeState(a state) [200]byte {
	panic(todo("TODO K-01: encode 25 little-endian lanes; FIPS 202 section 3.1.3"))
}

func theta(a *state) {
	panic(todo("TODO K-02: column parity and diffusion; FIPS 202 section 3.2.1"))
}

func rho(a *state) {
	panic(todo("TODO K-02: rotate each lane; FIPS 202 section 3.2.2"))
}

func pi(a *state) {
	panic(todo("TODO K-02: permute lane positions; FIPS 202 section 3.2.3"))
}

func chi(a *state) {
	panic(todo("TODO K-02: nonlinear row mapping; FIPS 202 section 3.2.4"))
}

// iota applies the round constant. The caller supplies 0 <= round < 24.
// Derive constants with Algorithm 5, or store the derived 24 constants.
func iota(a *state, round int) {
	panic(todo("TODO K-02: inject the round constant; FIPS 202 section 3.2.5"))
}

// permute applies 24 rounds numbered 0 through 23, in place.
func permute(a *state) {
	panic(todo("TODO K-03: compose theta, rho, pi, chi, iota; FIPS 202 section 3.3"))
}

// padTail returns one newly owned rate-byte block containing tail, domain
// suffix and pad10*1. Preconditions: len(tail) < rate, rate is one of
// 72,104,136,144,168 and suffix is 0x06 (SHA-3) or 0x1f (SHAKE).
// The suffix includes the FIRST padding bit; the last bit is still required.
// Never mutate or retain tail, including spare capacity beyond its length.
func padTail(tail []byte, rate int, suffix byte) []byte {
	panic(todo("TODO K-04: byte-aligned domain suffix and pad10*1; FIPS 202 sections 5.1, B.2"))
}

// sponge absorbs data into a zero state and squeezes outputLen bytes into
// newly owned storage. rate is in BYTES, not bits. Allowed rates are
// 72,104,136,144,168; allowed suffixes are 0x06 and 0x1f.
// Panic on unsupported rates/suffixes or negative outputLen. Zero output
// length is valid. Do not modify or retain data. Bound auxiliary storage
// independently of message length (apart from the returned output).
func sponge(data []byte, rate int, suffix byte, outputLen int) []byte {
	panic(todo("TODO K-05: absorb full blocks, pad the tail, squeeze; FIPS 202 sections 4-6"))
}
