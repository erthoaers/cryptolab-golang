// Test specifications: RFC 8017 / PKCS #1 v2.2 (November 2016) and Go 1.27.1.
// Individual cases cite sections; fixture provenance is in helpers_test.go.
package rsa

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func TestI2OSP(t *testing.T) {
	// RFC 8017 section 4.1; self-derived base-256 boundary cases.
	cases := []struct {
		x    int64
		n    int
		want []byte
	}{
		{0, 0, []byte{}}, {0, 2, []byte{0, 0}}, {1, 3, []byte{0, 0, 1}},
		{255, 1, []byte{255}}, {256, 2, []byte{1, 0}},
		{65535, 2, []byte{255, 255}}, {65536, 4, []byte{0, 1, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d_in_%d_bytes", tc.x, tc.n), func(t *testing.T) {
			defer failUnfinished(t)
			x := big.NewInt(tc.x)
			got, err := I2OSP(x, tc.n)
			if err != nil || len(got) != tc.n || !bytes.Equal(got, tc.want) {
				t.Fatalf("I2OSP = %x, %v; want %x", got, err, tc.want)
			}
			if len(got) > 0 {
				got[0] ^= 0xff
			}
			requireInt(t, x, big.NewInt(tc.x))
		})
	}
}

func TestI2OSPErrors(t *testing.T) {
	// RFC 8017 section 4.1 overflow plus the exercise's nil/sign/length policy.
	cases := []struct {
		name string
		x    *big.Int
		n    int
		want error
	}{
		{"nil", nil, 1, ErrInvalidInteger},
		{"negative", big.NewInt(-1), 1, ErrInvalidInteger},
		{"negative_length", big.NewInt(0), -1, ErrInvalidLength},
		{"zero_length_overflow", big.NewInt(1), 0, ErrIntegerTooLarge},
		{"one_byte_overflow", big.NewInt(256), 1, ErrIntegerTooLarge},
		{"two_byte_overflow", big.NewInt(65536), 2, ErrIntegerTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			before := tc.x.String()
			got, err := I2OSP(tc.x, tc.n)
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("got %x, %v; want nil, %v", got, err, tc.want)
			}
			if tc.x.String() != before {
				t.Fatal("input changed on failure")
			}
		})
	}
}

func TestOS2IP(t *testing.T) {
	// RFC 8017 section 4.2; self-derived bytes including leading zeros and >64 bits.
	cases := []struct {
		x    []byte
		want string
	}{
		{nil, "0"}, {[]byte{}, "0"}, {[]byte{0, 0}, "0"},
		{[]byte{0, 1, 0}, "256"}, {[]byte{255, 255}, "65535"},
		{[]byte{1, 0, 0, 0, 0, 0, 0, 0, 0}, "18446744073709551616"},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			defer failUnfinished(t)
			input := bytes.Clone(tc.x)
			got := OS2IP(input)
			want, _ := new(big.Int).SetString(tc.want, 10)
			requireInt(t, got, want)
			if !bytes.Equal(input, tc.x) {
				t.Fatal("input changed")
			}
			if len(input) > 0 {
				input[0] ^= 0xff
			}
			requireInt(t, got, want)
			got.SetInt64(-1)
			requireInt(t, OS2IP(tc.x), want)
		})
	}
}

func TestConversionMultiword(t *testing.T) {
	// RFC 8017 section 4; synthetic 256-byte input, independent SetBytes oracle.
	defer failUnfinished(t)
	input := make([]byte, 256)
	for i := range input {
		input[i] = byte(i)
	}
	want := new(big.Int).SetBytes(input)
	requireInt(t, OS2IP(input), want)
	got, err := I2OSP(want, len(input))
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("multiword I2OSP = %x, %v", got, err)
	}
}

var primitives = []struct {
	name    string
	private bool
	call    func(*PrivateKey, *big.Int) (*big.Int, error)
}{
	{"RSAEP", false, func(k *PrivateKey, x *big.Int) (*big.Int, error) { return RSAEP(&k.PublicKey, x) }},
	{"RSADP", true, RSADP}, {"RSADPCRT", true, RSADPCRT}, {"RSASP1", true, RSASP1},
	{"RSAVP1", false, func(k *PrivateKey, x *big.Int) (*big.Int, error) { return RSAVP1(&k.PublicKey, x) }},
}

func TestPrimitivesKnownAnswers(t *testing.T) {
	// RFC 8017 sections 5.1-5.2; fixed local answers include nonunits 53 and 61.
	for _, op := range primitives {
		t.Run(op.name, func(t *testing.T) {
			defer failUnfinished(t)
			for _, row := range answers {
				want := row.public
				if op.private {
					want = row.private
				}
				got, err := op.call(toyKey(), big.NewInt(row.x))
				if err != nil {
					t.Fatal(err)
				}
				requireInt(t, got, big.NewInt(want))
			}
		})
	}
}

func TestPrimitiveBounds(t *testing.T) {
	// RFC 8017 sections 5.1-5.2 require rejection, not reduction modulo n.
	for _, op := range primitives {
		t.Run(op.name, func(t *testing.T) {
			defer failUnfinished(t)
			for _, x := range []*big.Int{nil, big.NewInt(-1), big.NewInt(3233), big.NewInt(3234)} {
				key := toyKey()
				before := keySnapshot(key)
				input := x.String()
				got, err := op.call(key, x)
				if got != nil || !errors.Is(err, ErrRepresentativeOutOfRange) {
					t.Fatalf("input %v: got %v, %v", x, got, err)
				}
				if x.String() != input || !reflect.DeepEqual(before, keySnapshot(key)) {
					t.Fatal("inputs changed on failure")
				}
			}
		})
	}
}

func TestPrimitiveOwnership(t *testing.T) {
	// Local ownership policy for all RFC 8017 section 5 primitive entry points.
	for _, op := range primitives {
		t.Run(op.name, func(t *testing.T) {
			defer failUnfinished(t)
			key := toyKey()
			before := keySnapshot(key)
			x := big.NewInt(65)
			got, err := op.call(key, x)
			if err != nil || got == nil {
				t.Fatalf("got %v, %v", got, err)
			}
			if !reflect.DeepEqual(before, keySnapshot(key)) || x.Int64() != 65 {
				t.Fatal("inputs changed")
			}
			got.SetInt64(-1)
			if !reflect.DeepEqual(before, keySnapshot(key)) || x.Int64() != 65 {
				t.Fatal("result aliases inputs")
			}
		})
	}
}

func TestPrimitiveDifferential(t *testing.T) {
	// RFC 8017 section 5; exhaustive local 0..3232 corpus versus math/big.Exp.
	// Comparing each direction independently avoids accepting canceling errors.
	for _, op := range primitives {
		t.Run(op.name, func(t *testing.T) {
			defer failUnfinished(t)
			key := toyKey()
			exponent := big.NewInt(int64(key.E))
			if op.private {
				exponent = key.D
			}
			for i := int64(0); i < 3233; i++ {
				x := big.NewInt(i)
				want := new(big.Int).Exp(x, exponent, key.N)
				got, err := op.call(key, x)
				if err != nil {
					t.Fatalf("input %d: %v", i, err)
				}
				requireInt(t, got, want)
			}
		})
	}
}

func TestPrimitiveRepresentations(t *testing.T) {
	// RFC 8017 section 5.1.2: exercise each private representation separately.
	t.Run("RSADP", func(t *testing.T) {
		defer failUnfinished(t)
		key := toyKey()
		key.Primes = nil
		key.Precomputed = PrecomputedValues{}
		got, err := RSADP(key, big.NewInt(2790))
		if err != nil {
			t.Fatal(err)
		}
		requireInt(t, got, big.NewInt(65))
	})
	t.Run("RSADPCRT", func(t *testing.T) {
		defer failUnfinished(t)
		key := toyKey()
		key.D = nil
		got, err := RSADPCRT(key, big.NewInt(2790))
		if err != nil {
			t.Fatal(err)
		}
		requireInt(t, got, big.NewInt(65))
	})
}

func TestMultiwordKey(t *testing.T) {
	// Synthetic multiword case for sections 3 and 5: p=2^127-1, q=2^107-1.
	// This is an educational fixture, not a recommended key size or official KAT.
	defer failUnfinished(t)
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	q := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 107), big.NewInt(1))
	if !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		t.Fatal("nonprime test fixture")
	}
	n := new(big.Int).Mul(p, q)
	pm1 := new(big.Int).Sub(p, big.NewInt(1))
	qm1 := new(big.Int).Sub(q, big.NewInt(1))
	lambda := new(big.Int).Mul(pm1, qm1)
	lambda.Quo(lambda, new(big.Int).GCD(nil, nil, pm1, qm1))
	d := new(big.Int).ModInverse(big.NewInt(65537), lambda)
	if d == nil {
		t.Fatal("invalid fixture exponent")
	}
	key, err := NewPrivateKey(p, q, 65537)
	if err != nil || key == nil {
		t.Fatalf("NewPrivateKey = %v, %v", key, err)
	}
	requireInt(t, key.N, n)
	requireInt(t, key.D, d)
	requireInt(t, key.Precomputed.Dp, new(big.Int).Mod(d, pm1))
	requireInt(t, key.Precomputed.Dq, new(big.Int).Mod(d, qm1))
	requireInt(t, key.Precomputed.Qinv, new(big.Int).ModInverse(q, p))
	for _, op := range primitives {
		t.Run(op.name, func(t *testing.T) {
			defer failUnfinished(t)
			exponent := big.NewInt(65537)
			if op.private {
				exponent = d
			}
			for _, x := range []*big.Int{big.NewInt(0), big.NewInt(65), p, q, new(big.Int).Sub(n, big.NewInt(1))} {
				want := new(big.Int).Exp(x, exponent, n)
				got, err := op.call(key, x)
				if err != nil {
					t.Fatal(err)
				}
				requireInt(t, got, want)
			}
		})
	}
}

func TestHashSelection(t *testing.T) {
	// FIPS 180-4 (2015) section 6; wiring checked against standard hashes on a
	// local message. RSA hash choices: RFC 8017 Appendix B.1.
	for _, id := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA512_224, crypto.SHA512_256} {
		t.Run(id.String(), func(t *testing.T) {
			defer failUnfinished(t)
			h, err := newHash(id)
			if err != nil {
				t.Fatal(err)
			}
			oracle := id.New()
			for _, p := range [][]byte{[]byte("RSA "), []byte("hash selection")} {
				h.Write(p)
				oracle.Write(p)
			}
			if !bytes.Equal(h.Sum(nil), oracle.Sum(nil)) {
				t.Fatal("hash wiring mismatch")
			}
		})
	}
	t.Run("unsupported", func(t *testing.T) {
		defer failUnfinished(t)
		h, err := newHash(crypto.Hash(255))
		if h != nil || !errors.Is(err, ErrUnsupportedHash) {
			t.Fatalf("unsupported hash: %v, %v", h, err)
		}
	})
}

func TestMGF1(t *testing.T) {
	// RFC 8017 B.2.1; local seed, expected SHA-256 bytes independently generated
	// using Python hashlib.sha256(seed + counter.to_bytes(4, 'big')).
	expected, _ := hex.DecodeString("f08da0d3530ccdcc5ca5e6cdfe0437e469bf1ec68266b8c9634f0b6dfeb89bd252a986f64426452051e56a39597b0bc32f9e2fc89f55db9ef0153e70046f7c0c2e")
	for _, n := range []int{0, 1, 31, 32, 33, 65} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			defer failUnfinished(t)
			seed := []byte("rsa-mgf1")
			h := sha256.New()
			h.Write([]byte("must be reset"))
			got, err := mgf1(h, seed, n)
			if err != nil || !bytes.Equal(got, expected[:n]) || string(seed) != "rsa-mgf1" {
				t.Fatalf("MGF1(%d): %x, %v", n, got, err)
			}
		})
	}
	t.Run("negative", func(t *testing.T) {
		defer failUnfinished(t)
		got, err := mgf1(sha256.New(), nil, -1)
		if got != nil || !errors.Is(err, ErrInvalidLength) {
			t.Fatalf("negative length: %x, %v", got, err)
		}
	})
}
