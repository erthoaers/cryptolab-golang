package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	stdsha512 "crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"
)

// Specification: RFC 8032 (January 2017), sections 3, 5.1, 6.1, 7.1, 8.4.
// https://www.rfc-editor.org/rfc/rfc8032.html
// Official vectors live in vectors_test.go. Other cases are self-derived
// arithmetic/boundary fixtures or deterministic standard-library comparisons;
// they are not additional RFC or NIST conformance vectors.

func failUnfinished(t *testing.T) {
	t.Helper()
	if r := recover(); r != nil {
		if message, ok := r.(todo); ok {
			t.Fatalf("unfinished exercise: %s", message)
		}
		panic(r)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Oracle encoders deliberately use big-endian big.Int conversion plus a
// separate byte reversal, never the exercise's littleInt/littleBytes.
func oracleInt(b []byte) *big.Int {
	c := bytes.Clone(b)
	for i, j := 0, len(c)-1; i < j; i, j = i+1, j-1 {
		c[i], c[j] = c[j], c[i]
	}
	return new(big.Int).SetBytes(c)
}

func oracleBytes(x *big.Int, size int) []byte {
	b := x.FillBytes(make([]byte, size))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func requireInt(t *testing.T, got, want *big.Int) {
	t.Helper()
	if got == nil || got.Cmp(want) != 0 {
		t.Fatalf("integer = %v, want %v", got, want)
	}
}

func requirePoint(t *testing.T, got, want point) {
	t.Helper()
	requireInt(t, got.x, want.x)
	requireInt(t, got.y, want.y)
}

func pointState(p point) string { return fmt.Sprintf("%v,%v", p.x, p.y) }

// Self-derived from RFC 8032 section 3's affine addition with B+B;
// independently checked using Python modular integer arithmetic.
func twiceBase() point {
	return point{
		decimal("24727413235106541002554574571675588834622768167397638456726423682521233608206"),
		decimal("15549675580280190176352668710449542251549572066445060580507079593062643049417"),
	}
}

func TestVectorFixtures(t *testing.T) {
	// RFC 8032 section 7.1. Validate transcription using only the independent
	// standard library. Passing this does NOT exercise our Ed25519 implementation.
	lengths := []int{0, 1, 2, 1023, 64}
	if len(rfcVectors) != len(lengths) {
		t.Fatal("incomplete RFC vector set")
	}
	for i, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			seed, pub := unhex(t, v.seed), unhex(t, v.public)
			msg, sig := unhex(t, v.message), unhex(t, v.signature)
			if len(seed) != 32 || len(pub) != 32 || len(sig) != 64 || len(msg) != lengths[i] {
				t.Fatal("wrong fixture length")
			}
			key := stded25519.NewKeyFromSeed(seed)
			if !bytes.Equal(key[32:], pub) || !bytes.Equal(stded25519.Sign(key, msg), sig) || !stded25519.Verify(pub, msg, sig) {
				t.Fatal("RFC fixture disagrees with independent implementation")
			}
		})
	}
	// Check parameter transcription independently of the exercise constructors.
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	l := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), decimal("27742317777372353535851937790883648493"))
	requireInt(t, fieldPrime(), p)
	requireInt(t, groupOrder(), l)
	d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p))
	requireInt(t, curveD(), d.Mod(d, p))
	for _, tc := range encodedPoints() {
		b := tc.p
		encoded := oracleBytes(b.y, 32)
		encoded[31] |= byte(b.x.Bit(0)) << 7
		if !bytes.Equal(encoded, unhex(t, tc.encoded)) {
			t.Fatalf("incorrect point fixture: %s", tc.name)
		}
		x2, y2 := new(big.Int).Mul(b.x, b.x), new(big.Int).Mul(b.y, b.y)
		lhs := new(big.Int).Sub(y2, x2)
		rhs := new(big.Int).Mul(d, new(big.Int).Mul(x2, y2))
		rhs.Add(rhs, big.NewInt(1))
		requireInt(t, lhs.Mod(lhs, p), rhs.Mod(rhs, p))
	}
	// The y=2 negative fixture must truly have no square root for x.
	x2 := new(big.Int).Mul(d, big.NewInt(4))
	x2.Add(x2, big.NewInt(1))
	x2.ModInverse(x2, p).Mul(x2, big.NewInt(3)).Mod(x2, p)
	exponent := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	requireInt(t, new(big.Int).Exp(x2, exponent, p), new(big.Int).Sub(p, big.NewInt(1)))
}

func TestHashParts(t *testing.T) {
	// RFC 8032 sections 5.1.5-5.1.7; synthetic SHA-512 padding/block boundaries.
	// This checks the existing hash dependency and glue, not Ed25519 TODOs.
	for _, n := range []int{0, 1, 32, 64, 111, 112, 127, 128, 129, 255, 1023} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			in := make([]byte, n, n+64)
			for i := range in {
				in[i] = byte(i*17 + 3)
			}
			backing := in[:cap(in)]
			for i := n; i < len(backing); i++ {
				backing[i] = 0xa5
			}
			before := bytes.Clone(backing)
			got := hashParts(nil, in[:n/2], nil, in[n/2:])
			if got != stdsha512.Sum512(in) || !bytes.Equal(backing, before) {
				t.Fatal("hash mismatch or modified input")
			}
		})
	}
}

func TestLittleInt(t *testing.T) {
	// RFC 8032 section 5.1.2; self-derived little-endian cases.
	for _, s := range []string{"", "00", "0001", "010000", "ffffffffffffffff", "010000000000000001", rfcVectors[0].signature} {
		t.Run(s, func(t *testing.T) {
			defer failUnfinished(t)
			in := unhex(t, s)
			before := bytes.Clone(in)
			got := littleInt(in)
			want := oracleInt(in)
			requireInt(t, got, want)
			if !bytes.Equal(in, before) {
				t.Fatal("input modified")
			}
			if len(in) > 0 {
				in[0] ^= 255
			}
			requireInt(t, got, want)
		})
	}
}

func TestLittleBytes(t *testing.T) {
	// RFC 8032 section 5.1.2; fixed widths and multiword integers.
	for _, s := range []string{"", "0000", "010000", "0001", "ffffffffffffffff", rfcVectors[0].signature} {
		t.Run(s, func(t *testing.T) {
			defer failUnfinished(t)
			want := unhex(t, s)
			x := oracleInt(want)
			before := new(big.Int).Set(x)
			got, err := littleBytes(x, len(want))
			if err != nil || len(got) != len(want) || !bytes.Equal(got, want) {
				t.Fatalf("got %x, %v; want %x", got, err, want)
			}
			requireInt(t, x, before)
			if len(got) > 0 {
				got[0] ^= 255
			}
			requireInt(t, x, before)
		})
	}
}

func TestLittleBytesErrors(t *testing.T) {
	// Exercise API policy around the section 5.1.2 integer representation.
	for _, tc := range []struct {
		name string
		x    *big.Int
		n    int
		err  error
	}{
		{"nil", nil, 1, ErrInvalidInteger}, {"negative", big.NewInt(-1), 1, ErrInvalidInteger},
		{"length", big.NewInt(0), -1, ErrInvalidLength}, {"overflow", big.NewInt(256), 1, ErrIntegerTooLarge},
		{"zero_length", big.NewInt(1), 0, ErrIntegerTooLarge},
		{"256_bits", new(big.Int).Lsh(big.NewInt(1), 256), 32, ErrIntegerTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			before := fmt.Sprint(tc.x)
			got, err := littleBytes(tc.x, tc.n)
			if got != nil || !errors.Is(err, tc.err) || fmt.Sprint(tc.x) != before {
				t.Fatalf("got %x, %v; want nil, %v, unchanged input", got, err, tc.err)
			}
		})
	}
}

func encodedPoints() []struct {
	name    string
	p       point
	encoded string
} {
	b := basePoint()
	return []struct {
		name    string
		p       point
		encoded string
	}{
		{"identity", identity(), "0100000000000000000000000000000000000000000000000000000000000000"},
		{"base", b, "5866666666666666666666666666666666666666666666666666666666666666"},
		{"negative_base", point{new(big.Int).Sub(fieldPrime(), b.x), new(big.Int).Set(b.y)}, "58666666666666666666666666666666666666666666666666666666666666e6"},
		{"twice_base", twiceBase(), "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"},
		{"order_two", point{big.NewInt(0), new(big.Int).Sub(fieldPrime(), big.NewInt(1))}, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	}
}

func TestPointEncoding(t *testing.T) {
	// RFC 8032 sections 3, 5.1.2; self-derived encodings including the sign bit.
	for _, tc := range encodedPoints() {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			before := pointState(tc.p)
			got := encodePoint(tc.p)
			if !bytes.Equal(got[:], unhex(t, tc.encoded)) || pointState(tc.p) != before {
				t.Fatalf("wrong encoding %x or modified input", got)
			}
		})
	}
}

func TestPointDecoding(t *testing.T) {
	// RFC 8032 section 5.1.3. A small-order point is still a valid curve point.
	for _, tc := range encodedPoints() {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			in := unhex(t, tc.encoded)
			before := bytes.Clone(in)
			got, err := decodePoint(in)
			if err != nil {
				t.Fatal(err)
			}
			requirePoint(t, got, tc.p)
			if !bytes.Equal(in, before) {
				t.Fatal("input modified")
			}
			in[0] ^= 255
			requirePoint(t, got, tc.p)
		})
	}
}

func invalidEncodings() map[string][]byte {
	p := fieldPrime()
	negativeZero := make([]byte, 32)
	negativeZero[0] = 1
	negativeZero[31] = 128
	nonsquare := make([]byte, 32)
	nonsquare[0] = 2 // x^2=3/(4d+1) is nonsquare mod p.
	return map[string][]byte{
		"short": make([]byte, 31), "long": make([]byte, 33), "nil": nil,
		"y_equal_p": oracleBytes(p, 32), "y_above_p": oracleBytes(new(big.Int).Add(p, big.NewInt(1)), 32),
		"negative_zero": negativeZero, "nonsquare": nonsquare,
	}
}

func TestPointDecodingErrors(t *testing.T) {
	// RFC 8032 section 5.1.3, steps 1, 3 and 4; self-derived rejection cases.
	for name, in := range invalidEncodings() {
		t.Run(name, func(t *testing.T) {
			defer failUnfinished(t)
			before := bytes.Clone(in)
			got, err := decodePoint(in)
			if !errors.Is(err, ErrInvalidPoint) || got.x != nil || got.y != nil || !bytes.Equal(in, before) {
				t.Fatalf("got %v, %v; want zero point and encoding error, unchanged input", got, err)
			}
		})
	}
}

func TestPointAddition(t *testing.T) {
	// RFC 8032 sections 3 and 5.1.4; group identities and independent B+B fixture.
	b := basePoint()
	neg := point{new(big.Int).Sub(fieldPrime(), b.x), new(big.Int).Set(b.y)}
	for _, tc := range []struct {
		name       string
		p, q, want point
	}{
		{"right_identity", b, identity(), b}, {"left_identity", identity(), b, b},
		{"inverse", b, neg, identity()}, {"doubling_alias", b, b, twiceBase()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			beforeP, beforeQ := pointState(tc.p), pointState(tc.q)
			got := addPoints(tc.p, tc.q)
			requirePoint(t, got, tc.want)
			if pointState(tc.p) != beforeP || pointState(tc.q) != beforeQ {
				t.Fatal("input modified")
			}
			got.x.SetInt64(123)
			got.y.SetInt64(456)
			if pointState(tc.p) != beforeP || pointState(tc.q) != beforeQ {
				t.Fatal("result aliases input")
			}
		})
	}
}

func TestScalarMult(t *testing.T) {
	// RFC 8032 section 5.1, B has order L; general points may have order 2/4/8.
	b := basePoint()
	torsion := point{big.NewInt(0), new(big.Int).Sub(fieldPrime(), big.NewInt(1))}
	for _, tc := range []struct {
		name string
		p    point
		n    *big.Int
		want point
	}{
		{"zero", b, big.NewInt(0), identity()}, {"one", b, big.NewInt(1), b}, {"two", b, big.NewInt(2), twiceBase()},
		{"order", b, groupOrder(), identity()}, {"order_plus_one", b, new(big.Int).Add(groupOrder(), big.NewInt(1)), b},
		{"torsion_odd_L", torsion, groupOrder(), torsion}, {"torsion_even", torsion, big.NewInt(2), identity()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			before, nBefore := pointState(tc.p), tc.n.String()
			got := scalarMult(tc.p, tc.n)
			requirePoint(t, got, tc.want)
			if pointState(tc.p) != before || tc.n.String() != nBefore {
				t.Fatal("input modified")
			}
			got.x.SetInt64(123)
			got.y.SetInt64(456)
			if pointState(tc.p) != before || tc.n.String() != nBefore {
				t.Fatal("result aliases input")
			}
		})
	}
}

func TestExpandSeed(t *testing.T) {
	// RFC 8032 section 5.1.5 and section 7.1 seeds; independent SHA-512 oracle.
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			seed := [32]byte(unhex(t, v.seed))
			h := stdsha512.Sum512(seed[:])
			wantPrefix := [32]byte(h[32:])
			h[0] &= 248
			h[31] &= 63
			h[31] |= 64
			s, prefix := expandSeed(seed)
			requireInt(t, s, oracleInt(h[:32]))
			if prefix != wantPrefix {
				t.Fatal("nonce prefix changed")
			}
			s.SetInt64(0)
			again, _ := expandSeed(seed)
			requireInt(t, again, oracleInt(h[:32]))
		})
	}
}

func TestPublicKeyRFC8032(t *testing.T) {
	// RFC 8032 sections 5.1.5 and 7.1.
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			got := PublicKeyFromSeed([32]byte(unhex(t, v.seed)))
			if !bytes.Equal(got[:], unhex(t, v.public)) {
				t.Fatalf("public key = %x, want %s", got, v.public)
			}
		})
	}
}

func TestSignRFC8032(t *testing.T) {
	// RFC 8032 sections 5.1.6 and 7.1; compare exact deterministic signatures.
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			msg := unhex(t, v.message)
			before := bytes.Clone(msg)
			seed := [32]byte(unhex(t, v.seed))
			got := Sign(seed, msg)
			if !bytes.Equal(got[:], unhex(t, v.signature)) || !bytes.Equal(msg, before) {
				t.Fatal("signature mismatch or modified message")
			}
			if Sign(seed, msg) != got {
				t.Fatal("nondeterministic signature")
			}
		})
	}
}

func TestVerifyRFC8032(t *testing.T) {
	// RFC 8032 sections 5.1.7 and 7.1; no local Sign call hides verifier errors.
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			pub, msg, sig := unhex(t, v.public), unhex(t, v.message), unhex(t, v.signature)
			if !Verify(pub, msg, sig) {
				t.Fatal("official signature rejected")
			}
			if hex.EncodeToString(pub) != v.public || hex.EncodeToString(msg) != v.message || hex.EncodeToString(sig) != v.signature {
				t.Fatal("verification modified input")
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	// RFC 8032 sections 5.1.3, 5.1.7 and 8.4. Mutations of official TEST 2.
	v := rfcVectors[1]
	pub, msg, sig := unhex(t, v.public), unhex(t, v.message), unhex(t, v.signature)
	type inputs struct{ pub, msg, sig []byte }
	cases := map[string]inputs{
		"wrong_message": {pub, []byte{0x73}, sig}, "wrong_key": {unhex(t, rfcVectors[0].public), msg, sig},
		"short_signature": {pub, msg, sig[:63]}, "long_signature": {pub, msg, append(bytes.Clone(sig), 0)},
		"empty_signature": {pub, msg, nil},
	}
	for name, in := range invalidEncodings() {
		cases["public_"+name] = inputs{in, msg, sig}
		if len(in) == 32 {
			bad := bytes.Clone(sig)
			copy(bad[:32], in)
			cases["R_"+name] = inputs{pub, msg, bad}
		}
	}
	for name, s := range map[string]*big.Int{
		"S_equal_L": groupOrder(), "S_plus_L": new(big.Int).Add(oracleInt(sig[32:]), groupOrder()),
		"S_high_bit": new(big.Int).Lsh(big.NewInt(1), 255),
	} {
		bad := bytes.Clone(sig)
		copy(bad[32:], oracleBytes(s, 32))
		cases[name] = inputs{pub, msg, bad}
	}
	for _, i := range []int{0, 31, 32, 63} {
		bad := bytes.Clone(sig)
		bad[i] ^= 1
		cases[fmt.Sprintf("flip_byte_%d", i)] = inputs{pub, msg, bad}
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer failUnfinished(t)
			a, b, c := bytes.Clone(in.pub), bytes.Clone(in.msg), bytes.Clone(in.sig)
			if Verify(in.pub, in.msg, in.sig) {
				t.Fatal("invalid signature accepted")
			}
			if !bytes.Equal(a, in.pub) || !bytes.Equal(b, in.msg) || !bytes.Equal(c, in.sig) {
				t.Fatal("input modified on rejection")
			}
		})
	}
}

func TestVerifyPolicy(t *testing.T) {
	// RFC 8032 section 5.1.7 permits two equations. Fix the exercise's choice:
	// uncofactored equation with canonical encodings, no subgroup rejection.
	// A=identity, S=0: R=identity passes; R=order-two fails (but would pass
	// the cofactored equation). These are self-derived policy cases, not keys
	// generated from a seed and not a standard-library acceptance oracle.
	pub := make([]byte, 32)
	pub[0] = 1
	for _, tc := range []struct {
		name string
		r    []byte
		want bool
	}{
		{"identity", pub, true},
		{"order_two_R", oracleBytes(new(big.Int).Sub(fieldPrime(), big.NewInt(1)), 32), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			sig := make([]byte, 64)
			copy(sig, tc.r)
			if Verify(pub, []byte("policy"), sig) != tc.want {
				t.Fatal("verification policy mismatch")
			}
		})
	}
}

func TestAgainstStandard(t *testing.T) {
	// RFC 8032 sections 5.1.5-5.1.7; synthetic valid keys/messages compared
	// with Go's independent implementation. Not a malformed-input policy oracle.
	for _, n := range []int{0, 1, 47, 48, 63, 64, 79, 80, 111, 112, 127, 128, 129, 255, 1024} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			defer failUnfinished(t)
			var seed [32]byte
			for i := range seed {
				seed[i] = byte(i*13 + n)
			}
			msg := make([]byte, n, n+64)
			for i := range msg {
				msg[i] = byte(i*29 + n)
			}
			backing := msg[:cap(msg)]
			for i := n; i < len(backing); i++ {
				backing[i] = 0xa5
			}
			before := bytes.Clone(backing)
			key := stded25519.NewKeyFromSeed(seed[:])
			want := stded25519.Sign(key, msg)
			pub := PublicKeyFromSeed(seed)
			sig := Sign(seed, msg)
			if !bytes.Equal(pub[:], key[32:]) || !bytes.Equal(sig[:], want) {
				t.Fatal("key or signature mismatch")
			}
			if !stded25519.Verify(pub[:], msg, sig[:]) || !Verify(key[32:], msg, want) {
				t.Fatal("interoperability failed")
			}
			if !bytes.Equal(backing, before) {
				t.Fatal("message or spare capacity modified")
			}
		})
	}
}
