package rsa

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"
)

// References: RFC 8017 / PKCS #1 v2.2 (November 2016), sections 3.1,
// 5.1.2 and 5.2.1 specify the RSA domain and private operations, not this
// sampler. The multiplicative blinding identity is also illustrated by
// Go 1.19.13 crypto/rsa's decrypt function (a historical implementation):
// https://github.com/golang/go/blob/go1.19.13/src/crypto/rsa/rsa.go
// Rejection sampling, nil-reader handling and error precedence below are
// local exercise contracts, not current Go crypto/rsa API requirements.
// Small integers are local fixtures, checked with Python integer arithmetic;
// large public test-only keys are documented in helpers_test.go. These are
// functional tests, not official vectors or timing/security acceptance.

func TestBlindingVectorFixtures(t *testing.T) {
	// n=61*53, e=17, d=413, x=2790, x^d mod n=65.
	for _, tc := range []struct {
		r, rInv, rPower, blinded, privateResult int64
	}{
		{2, 1617, 1752, 3017, 130},
		{42, 77, 2557, 2032, 2730},
		{3232, 3232, 3232, 443, 3168},
	} {
		t.Run(fmt.Sprint(tc.r), func(t *testing.T) {
			if tc.r*tc.rInv%3233 != 1 || smallPower(tc.r, 17, 3233) != tc.rPower {
				t.Fatal("incorrect factor or inverse fixture")
			}
			if 2790*tc.rPower%3233 != tc.blinded || smallPower(tc.blinded, 413, 3233) != tc.privateResult {
				t.Fatal("incorrect blinded private-operation fixture")
			}
			if tc.privateResult*tc.rInv%3233 != 65 {
				t.Fatal("unblinding did not recover the expected representative")
			}
		})
	}
}

func TestBlindingFactor(t *testing.T) {
	for _, tc := range []struct {
		name          string
		n             int64
		input         []byte
		want, wantInv int64
	}{
		{"one", 3233, []byte{0, 1}, 1, 1},
		{"even_factor", 3233, []byte{0, 2}, 2, 1617},
		{"composite_factor", 3233, []byte{0, 42}, 42, 77},
		{"n_minus_one", 3233, []byte{0x0c, 0xa0}, 3232, 3232},
		{"mask_excess_bits", 3233, []byte{0xf0, 2}, 2, 1617},
		{"byte_aligned_modulus", 143, []byte{2}, 2, 72},
		{"nine_bit_modulus", 323, []byte{0xfe, 2}, 2, 162},
		{"reject_zero", 3233, []byte{0, 0, 0, 42}, 42, 77},
		{"reject_n", 3233, []byte{0x0c, 0xa1, 0, 42}, 42, 77},
		{"reject_above_n", 3233, []byte{0x0c, 0xa3, 0, 42}, 42, 77},
		{"reject_factor_p", 3233, []byte{0, 61, 0, 42}, 42, 77},
		{"reject_factor_q", 3233, []byte{0, 53, 0, 42}, 42, 77},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			n := big.NewInt(tc.n)
			input := append(bytes.Clone(tc.input), 0xaa)
			random := bytes.NewReader(input)
			r, rInv, err := randomBlindingFactor(random, n)
			if err != nil {
				t.Fatal(err)
			}
			requireInt(t, r, big.NewInt(tc.want))
			requireInt(t, rInv, big.NewInt(tc.wantInv))
			if n.Cmp(big.NewInt(tc.n)) != 0 || random.Len() != 1 {
				t.Fatal("changed modulus or consumed the wrong candidate bytes")
			}
			if new(big.Int).Mod(new(big.Int).Mul(r, rInv), n).Cmp(big.NewInt(1)) != 0 {
				t.Fatal("returned values are not multiplicative inverses")
			}
			// Even when r and rInv have equal values, their storage is independent.
			r.SetInt64(0)
			requireInt(t, rInv, big.NewInt(tc.wantInv))
			rInv.SetInt64(0)
			requireInt(t, n, big.NewInt(tc.n))
		})
	}
}

func TestBlindingFactorLargeModulus(t *testing.T) {
	for _, bits := range []int{2048, 2049} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			defer failUnfinished(t)
			n := new(big.Int).Set(standardFixture(t, bits).N)
			want := new(big.Int).Sub(n, big.NewInt(1))
			input := want.FillBytes(make([]byte, (n.BitLen()+7)/8))
			r, rInv, err := randomBlindingFactor(bytes.NewReader(input), n)
			if err != nil {
				t.Fatal(err)
			}
			requireInt(t, r, want)
			requireInt(t, rInv, want)
			requireInt(t, n, new(big.Int).Add(want, big.NewInt(1)))
		})
	}
}

type blindingCountingReader struct {
	reader io.Reader
	calls  int
	chunk  int
}

func (r *blindingCountingReader) Read(p []byte) (int, error) {
	r.calls++
	if r.chunk > 0 && len(p) > r.chunk {
		p = p[:r.chunk]
	}
	return r.reader.Read(p)
}

func TestBlindingFactorInvalidModulus(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    *big.Int
	}{
		{"nil", nil},
		{"negative", big.NewInt(-3233)},
		{"zero", big.NewInt(0)},
		{"one", big.NewInt(1)},
		{"two", big.NewInt(2)},
		{"even", big.NewInt(3232)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			random := &blindingCountingReader{reader: failedReader{}}
			r, rInv, err := randomBlindingFactor(random, tc.n)
			if r != nil || rInv != nil || !errors.Is(err, ErrInvalidKey) || random.calls != 0 {
				t.Fatalf("invalid modulus: r=%v, rInv=%v, err=%v, reads=%d", r, rInv, err, random.calls)
			}
		})
	}
}

func TestBlindingFactorReader(t *testing.T) {
	t.Run("fragmented_reads", func(t *testing.T) {
		defer failUnfinished(t)
		random := &blindingCountingReader{reader: bytes.NewReader([]byte{0, 42}), chunk: 1}
		r, rInv, err := randomBlindingFactor(random, big.NewInt(3233))
		if err != nil {
			t.Fatal(err)
		}
		requireInt(t, r, big.NewInt(42))
		requireInt(t, rInv, big.NewInt(77))
	})
	for _, tc := range []struct {
		name   string
		random io.Reader
		want   error
	}{
		{"nil", nil, ErrInvalidOptions},
		{"failed", failedReader{}, errEntropy},
		{"eof", bytes.NewReader(nil), io.EOF},
		{"short", bytes.NewReader([]byte{0}), io.ErrUnexpectedEOF},
		{"error_after_rejection", io.MultiReader(bytes.NewReader([]byte{0, 53}), failedReader{}), errEntropy},
		{"short_after_rejection", bytes.NewReader([]byte{0, 53, 0}), io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			r, rInv, err := randomBlindingFactor(tc.random, big.NewInt(3233))
			if r != nil || rInv != nil || !errors.Is(err, tc.want) {
				t.Fatalf("reader failure: r=%v, rInv=%v, err=%v; want %v", r, rInv, err, tc.want)
			}
		})
	}
}
