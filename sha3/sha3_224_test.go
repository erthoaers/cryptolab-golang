package sha3

import (
	"bytes"
	stdsha3 "crypto/sha3"
	"fmt"
	"testing"
)

// Specification: FIPS 202 (August 2015), section 6.1, and Appendix B.2.
// https://csrc.nist.gov/pubs/fips/202/final
// Official fixtures: NIST CAVP CAVS 19.0 byte-oriented vectors, January 2016.
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
// Source archive: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
// Selected vectors are in testdata/sha3_224.json; each names its original .rsp and Len/COUNT.
// Other cases below are synthetic boundary/differential cases, not NIST vectors.

func TestSum224VectorFixtures(t *testing.T) {
	// Verify transcription with an independent implementation only.
	// A pass here is NOT acceptance of the exercise implementation.
	for _, v := range vectors(t, "sha3_224") {
		t.Run(v.Source+"/"+v.Case, func(t *testing.T) {
			want := unhex(t, v.Output)
			if len(want) == 0 || v.Source == "" || v.Case == "" {
				t.Fatal("invalid fixture")
			}
			if got := oracle224(unhex(t, v.Message), len(want)); !bytes.Equal(got, want) {
				t.Fatalf("fixture mismatch: %x, want %x", got, want)
			}
		})
	}
}

func TestSum224KnownAnswers(t *testing.T) {
	for _, v := range vectors(t, "sha3_224") {
		t.Run(v.Source+"/"+v.Case, func(t *testing.T) {
			defer failUnfinished(t)
			want := unhex(t, v.Output)
			if got := digest224(unhex(t, v.Message), len(want)); !bytes.Equal(got, want) {
				t.Fatalf("digest224 = %x, want %x", got, want)
			}
		})
	}
}

func TestSum224Boundaries(t *testing.T) {
	// Rate boundaries catch a missing extra padded block at an exact multiple.
	for _, n := range []int{0, 1, 7, 8, BlockSize224 - 2, BlockSize224 - 1, BlockSize224, BlockSize224 + 1, 2*BlockSize224 - 1, 2 * BlockSize224, 2*BlockSize224 + 1, 4096} {
		for _, outLen := range []int{Size224} {
			t.Run(fmt.Sprintf("input=%d/output=%d", n, outLen), func(t *testing.T) {
				defer failUnfinished(t)
				in := make([]byte, n, n+64)
				backing := in[:cap(in)]
				for i := range backing {
					backing[i] = byte(i*17 + 3)
				}
				before := bytes.Clone(backing)
				want := oracle224(in, outLen)
				got := digest224(in, outLen)
				if !bytes.Equal(got, want) {
					t.Fatalf("digest224 = %x, want %x", got, want)
				}
				if !bytes.Equal(backing, before) {
					t.Fatal("input or spare capacity modified")
				}
				if again := digest224(in, outLen); !bytes.Equal(again, want) {
					t.Fatal("state leaked between calls")
				}
				for i := range backing {
					backing[i] ^= 0xff
				}
				if !bytes.Equal(got, want) {
					t.Fatal("output aliases input")
				}
			})
		}
	}
}

func TestSum224NilAndEmpty(t *testing.T) {
	defer failUnfinished(t)
	if !bytes.Equal(digest224(nil, 32), digest224([]byte{}, 32)) {
		t.Fatal("nil differs from empty message")
	}
}
func digest224(in []byte, _ int) []byte { out := Sum224(in); return out[:] }
func oracle224(in []byte, _ int) []byte { out := stdsha3.Sum224(in); return out[:] }

func TestSum224Parameters(t *testing.T) {
	// FIPS 202 section 6.1: c=2d and r+c=1600, converted to bytes.
	if Size224 != 28 || BlockSize224 != 144 || 8*BlockSize224+16*Size224 != 1600 {
		t.Fatal("wrong parameters")
	}
}
