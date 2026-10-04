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
// Selected vectors are in testdata/sha3_384.json; each names its original .rsp and Len/COUNT.
// Other cases below are synthetic boundary/differential cases, not NIST vectors.

func TestSum384VectorFixtures(t *testing.T) {
	// Verify transcription with an independent implementation only.
	// A pass here is NOT acceptance of the exercise implementation.
	for _, v := range vectors(t, "sha3_384") {
		t.Run(v.Source+"/"+v.Case, func(t *testing.T) {
			want := unhex(t, v.Output)
			if len(want) == 0 || v.Source == "" || v.Case == "" {
				t.Fatal("invalid fixture")
			}
			if got := oracle384(unhex(t, v.Message), len(want)); !bytes.Equal(got, want) {
				t.Fatalf("fixture mismatch: %x, want %x", got, want)
			}
		})
	}
}

func TestSum384KnownAnswers(t *testing.T) {
	for _, v := range vectors(t, "sha3_384") {
		t.Run(v.Source+"/"+v.Case, func(t *testing.T) {
			defer failUnfinished(t)
			want := unhex(t, v.Output)
			if got := digest384(unhex(t, v.Message), len(want)); !bytes.Equal(got, want) {
				t.Fatalf("digest384 = %x, want %x", got, want)
			}
		})
	}
}

func TestSum384Boundaries(t *testing.T) {
	// Rate boundaries catch a missing extra padded block at an exact multiple.
	for _, n := range []int{0, 1, 7, 8, BlockSize384 - 2, BlockSize384 - 1, BlockSize384, BlockSize384 + 1, 2*BlockSize384 - 1, 2 * BlockSize384, 2*BlockSize384 + 1, 4096} {
		for _, outLen := range []int{Size384} {
			t.Run(fmt.Sprintf("input=%d/output=%d", n, outLen), func(t *testing.T) {
				defer failUnfinished(t)
				in := make([]byte, n, n+64)
				backing := in[:cap(in)]
				for i := range backing {
					backing[i] = byte(i*17 + 3)
				}
				before := bytes.Clone(backing)
				want := oracle384(in, outLen)
				got := digest384(in, outLen)
				if !bytes.Equal(got, want) {
					t.Fatalf("digest384 = %x, want %x", got, want)
				}
				if !bytes.Equal(backing, before) {
					t.Fatal("input or spare capacity modified")
				}
				if again := digest384(in, outLen); !bytes.Equal(again, want) {
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

func TestSum384NilAndEmpty(t *testing.T) {
	defer failUnfinished(t)
	if !bytes.Equal(digest384(nil, 32), digest384([]byte{}, 32)) {
		t.Fatal("nil differs from empty message")
	}
}
func digest384(in []byte, _ int) []byte { out := Sum384(in); return out[:] }
func oracle384(in []byte, _ int) []byte { out := stdsha3.Sum384(in); return out[:] }

func TestSum384Parameters(t *testing.T) {
	// FIPS 202 section 6.1: c=2d and r+c=1600, converted to bytes.
	if Size384 != 48 || BlockSize384 != 104 || 8*BlockSize384+16*Size384 != 1600 {
		t.Fatal("wrong parameters")
	}
}
