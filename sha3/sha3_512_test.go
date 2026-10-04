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
// Selected vectors are in testdata/sha3_512.json; each names its original .rsp and Len/COUNT.
// Other cases below are synthetic boundary/differential cases, not NIST vectors.

func TestSum512VectorFixtures(t *testing.T) {
	// Verify transcription with an independent implementation only.
	// A pass here is NOT acceptance of the exercise implementation.
	for _, v := range vectors(t, "sha3_512") {
		t.Run(v.Source+"/"+v.Case, func(t *testing.T) {
			want := unhex(t, v.Output)
			if len(want) == 0 || v.Source == "" || v.Case == "" {
				t.Fatal("invalid fixture")
			}
			if got := oracle512(unhex(t, v.Message), len(want)); !bytes.Equal(got, want) {
				t.Fatalf("fixture mismatch: %x, want %x", got, want)
			}
		})
	}
}

func TestSum512KnownAnswers(t *testing.T) {
	for _, v := range vectors(t, "sha3_512") {
		t.Run(v.Source+"/"+v.Case, func(t *testing.T) {
			defer failUnfinished(t)
			want := unhex(t, v.Output)
			if got := digest512(unhex(t, v.Message), len(want)); !bytes.Equal(got, want) {
				t.Fatalf("digest512 = %x, want %x", got, want)
			}
		})
	}
}

func TestSum512Boundaries(t *testing.T) {
	// Rate boundaries catch a missing extra padded block at an exact multiple.
	for _, n := range []int{0, 1, 7, 8, BlockSize512 - 2, BlockSize512 - 1, BlockSize512, BlockSize512 + 1, 2*BlockSize512 - 1, 2 * BlockSize512, 2*BlockSize512 + 1, 4096} {
		for _, outLen := range []int{Size512} {
			t.Run(fmt.Sprintf("input=%d/output=%d", n, outLen), func(t *testing.T) {
				defer failUnfinished(t)
				in := make([]byte, n, n+64)
				backing := in[:cap(in)]
				for i := range backing {
					backing[i] = byte(i*17 + 3)
				}
				before := bytes.Clone(backing)
				want := oracle512(in, outLen)
				got := digest512(in, outLen)
				if !bytes.Equal(got, want) {
					t.Fatalf("digest512 = %x, want %x", got, want)
				}
				if !bytes.Equal(backing, before) {
					t.Fatal("input or spare capacity modified")
				}
				if again := digest512(in, outLen); !bytes.Equal(again, want) {
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

func TestSum512NilAndEmpty(t *testing.T) {
	defer failUnfinished(t)
	if !bytes.Equal(digest512(nil, 32), digest512([]byte{}, 32)) {
		t.Fatal("nil differs from empty message")
	}
}
func digest512(in []byte, _ int) []byte { out := Sum512(in); return out[:] }
func oracle512(in []byte, _ int) []byte { out := stdsha3.Sum512(in); return out[:] }

func TestSum512Parameters(t *testing.T) {
	// FIPS 202 section 6.1: c=2d and r+c=1600, converted to bytes.
	if Size512 != 64 || BlockSize512 != 72 || 8*BlockSize512+16*Size512 != 1600 {
		t.Fatal("wrong parameters")
	}
}
