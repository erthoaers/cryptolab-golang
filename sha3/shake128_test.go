package sha3

import (
	"bytes"
	stdsha3 "crypto/sha3"
	"fmt"
	"testing"
)

// Specification: FIPS 202 (August 2015), section 6.2, and Appendix B.2.
// https://csrc.nist.gov/pubs/fips/202/final
// Official fixtures: NIST CAVP CAVS 19.0 byte-oriented vectors, January 2016.
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
// Source archive: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip
// Selected vectors are in testdata/shake128.json; each names its original .rsp and Len/COUNT.
// Other cases below are synthetic boundary/differential cases, not NIST vectors.

func TestSumSHAKE128VectorFixtures(t *testing.T) {
	// Verify transcription with an independent implementation only.
	// A pass here is NOT acceptance of the exercise implementation.
	for _, v := range vectors(t, "shake128") {
		t.Run(v.Source+"/"+v.Case, func(t *testing.T) {
			want := unhex(t, v.Output)
			if len(want) == 0 || v.Source == "" || v.Case == "" {
				t.Fatal("invalid fixture")
			}
			if got := oracleSHAKE128(unhex(t, v.Message), len(want)); !bytes.Equal(got, want) {
				t.Fatalf("fixture mismatch: %x, want %x", got, want)
			}
		})
	}
}

func TestSumSHAKE128KnownAnswers(t *testing.T) {
	for _, v := range vectors(t, "shake128") {
		t.Run(v.Source+"/"+v.Case, func(t *testing.T) {
			defer failUnfinished(t)
			want := unhex(t, v.Output)
			if got := digestSHAKE128(unhex(t, v.Message), len(want)); !bytes.Equal(got, want) {
				t.Fatalf("digestSHAKE128 = %x, want %x", got, want)
			}
		})
	}
}

func TestSumSHAKE128Boundaries(t *testing.T) {
	// Rate boundaries catch a missing extra padded block at an exact multiple.
	for _, n := range []int{0, 1, 7, 8, BlockSizeSHAKE128 - 2, BlockSizeSHAKE128 - 1, BlockSizeSHAKE128, BlockSizeSHAKE128 + 1, 2*BlockSizeSHAKE128 - 1, 2 * BlockSizeSHAKE128, 2*BlockSizeSHAKE128 + 1, 4096} {
		for _, outLen := range []int{0, 1, 31, 32, BlockSizeSHAKE128 - 1, BlockSizeSHAKE128, BlockSizeSHAKE128 + 1, 2*BlockSizeSHAKE128 + 1} {
			t.Run(fmt.Sprintf("input=%d/output=%d", n, outLen), func(t *testing.T) {
				defer failUnfinished(t)
				in := make([]byte, n, n+64)
				backing := in[:cap(in)]
				for i := range backing {
					backing[i] = byte(i*17 + 3)
				}
				before := bytes.Clone(backing)
				want := oracleSHAKE128(in, outLen)
				got := digestSHAKE128(in, outLen)
				if !bytes.Equal(got, want) {
					t.Fatalf("digestSHAKE128 = %x, want %x", got, want)
				}
				if !bytes.Equal(backing, before) {
					t.Fatal("input or spare capacity modified")
				}
				if again := digestSHAKE128(in, outLen); !bytes.Equal(again, want) {
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

func TestSumSHAKE128NilAndEmpty(t *testing.T) {
	defer failUnfinished(t)
	if !bytes.Equal(digestSHAKE128(nil, 32), digestSHAKE128([]byte{}, 32)) {
		t.Fatal("nil differs from empty message")
	}
}
func digestSHAKE128(in []byte, n int) []byte { return SumSHAKE128(in, n) }
func oracleSHAKE128(in []byte, n int) []byte { return stdsha3.SumSHAKE128(in, n) }

func TestSumSHAKE128NegativeLength(t *testing.T) {
	// API contract, not a FIPS bit-string vector. TODO panic is NOT success.
	defer func() {
		r := recover()
		if message, ok := r.(todo); ok {
			t.Fatalf("unfinished exercise: %s", message)
		}
		if r == nil {
			t.Fatal("negative output length did not panic")
		}
	}()
	SumSHAKE128([]byte("abc"), -1)
}

func TestSumSHAKE128OutputPrefix(t *testing.T) {
	defer failUnfinished(t)
	msg := []byte("abc")
	short := SumSHAKE128(msg, BlockSizeSHAKE128-1)
	long := SumSHAKE128(msg, 3*BlockSizeSHAKE128+1)
	if len(long) != 3*BlockSizeSHAKE128+1 || !bytes.Equal(short, long[:BlockSizeSHAKE128-1]) {
		t.Fatal("XOF output length changed its prefix")
	}
	before := bytes.Clone(long)
	short[0] ^= 0xff
	if !bytes.Equal(long, before) {
		t.Fatal("outputs share mutable storage")
	}
}
