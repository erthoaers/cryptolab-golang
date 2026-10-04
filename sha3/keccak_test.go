package sha3

import (
	"bytes"
	stdsha3 "crypto/sha3"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// Specification: FIPS 202 (August 2015), sections 3-6, Appendix B.
// https://csrc.nist.gov/pubs/fips/202/final
// All 24 rounds' official intermediate values are transcribed from:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf
// The transcribed states are stored in testdata/nist_sha3_256_empty.json.
// Padding/encoding and differential cases are self-derived boundary fixtures.

type roundFixture struct{ Theta, Rho, Pi, Chi, Iota string }
type permutationFixture struct {
	Source, Initial, Final string
	Rounds                 []roundFixture
}

func fixture(t *testing.T) permutationFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/nist_sha3_256_empty.json")
	if err != nil {
		t.Fatal(err)
	}
	var f permutationFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Rounds) != 24 || f.Source != "SHA3-256_Msg0.pdf" {
		t.Fatal("incomplete official fixture")
	}
	return f
}

// Decode fixture bytes independently so later steps can be tested before K-01.
func fixtureState(t *testing.T, s string) state {
	t.Helper()
	b := unhex(t, s)
	if len(b) != 200 {
		t.Fatal("state must contain 200 bytes")
	}
	var a state
	for i := range a {
		a[i] = binary.LittleEndian.Uint64(b[i*8 : (i+1)*8])
	}
	return a
}

func TestVectorFixtures(t *testing.T) {
	// Structural and final digest checks only; intermediate values come from
	// the NIST PDF cited above. No algorithm TODO is called here.
	f := fixture(t)
	initial := fixtureState(t, f.Initial)
	var want state
	want[0], want[16] = 6, 0x8000000000000000
	if initial != want {
		t.Fatal("wrong initial padded state")
	}
	for _, r := range f.Rounds {
		for _, s := range []string{r.Theta, r.Rho, r.Pi, r.Chi, r.Iota} {
			fixtureState(t, s)
		}
	}
	final := unhex(t, f.Final)
	if len(final) != 200 || f.Final != f.Rounds[23].Iota {
		t.Fatal("final state mismatch")
	}
	sum := stdsha3.Sum256(nil)
	if !bytes.Equal(final[:32], sum[:]) {
		t.Fatal("final digest disagrees with independent implementation")
	}
}

func TestDecodeState(t *testing.T) {
	// Sections 3.1.2 and B.1: a distinct byte pattern detects lane/byte order.
	defer failUnfinished(t)
	var in [200]byte
	var want state
	for i := range in {
		in[i] = byte(i)
		want[i/8] |= uint64(in[i]) << uint(8*(i%8))
	}
	if got := decodeState(in); got != want {
		t.Fatalf("state = %x, want %x", got, want)
	}
}

func TestEncodeState(t *testing.T) {
	// Section 3.1.3; use independently constructed lanes, no decodeState call.
	defer failUnfinished(t)
	var in state
	var want [200]byte
	for i := range want {
		want[i] = byte(199 - i)
		in[i/8] |= uint64(want[i]) << uint(8*(i%8))
	}
	if got := encodeState(in); got != want {
		t.Fatalf("bytes = %x, want %x", got, want)
	}
}

func checkStep(t *testing.T, step string, apply func(*state, int)) {
	t.Helper()
	f := fixture(t)
	previous := f.Initial
	for i, r := range f.Rounds {
		pairs := map[string][2]string{
			"theta": {previous, r.Theta}, "rho": {r.Theta, r.Rho},
			"pi": {r.Rho, r.Pi}, "chi": {r.Pi, r.Chi}, "iota": {r.Chi, r.Iota},
		}
		pair := pairs[step]
		t.Run(fmt.Sprintf("round=%02d", i), func(t *testing.T) {
			defer failUnfinished(t)
			a := fixtureState(t, pair[0])
			apply(&a, i)
			if want := fixtureState(t, pair[1]); a != want {
				t.Fatalf("%s = %x, want %x", step, a, want)
			}
		})
		previous = r.Iota
	}
}

func TestTheta(t *testing.T) { checkStep(t, "theta", func(a *state, _ int) { theta(a) }) }
func TestRho(t *testing.T)   { checkStep(t, "rho", func(a *state, _ int) { rho(a) }) }
func TestPi(t *testing.T)    { checkStep(t, "pi", func(a *state, _ int) { pi(a) }) }
func TestChi(t *testing.T)   { checkStep(t, "chi", func(a *state, _ int) { chi(a) }) }
func TestIota(t *testing.T)  { checkStep(t, "iota", iota) }

func TestPermute(t *testing.T) {
	defer failUnfinished(t)
	f := fixture(t)
	a := fixtureState(t, f.Initial)
	permute(&a)
	if want := fixtureState(t, f.Final); a != want {
		t.Fatalf("permutation = %x, want %x", a, want)
	}
}

func TestPadTail(t *testing.T) {
	// Appendix B.2 Table 6: q=1, q=2 and q>2, for all five rates.
	for _, rate := range []int{72, 104, 136, 144, 168} {
		for _, suffix := range []byte{0x06, 0x1f} {
			for _, n := range []int{0, 1, rate - 3, rate - 2, rate - 1} {
				t.Run(fmt.Sprintf("rate=%d/suffix=%x/tail=%d", rate, suffix, n), func(t *testing.T) {
					defer failUnfinished(t)
					backing := bytes.Repeat([]byte{0xa3}, rate+8)
					before := bytes.Clone(backing)
					out := padTail(backing[:n], rate, suffix)
					padding := []byte{suffix | 0x80}
					if n < rate-1 {
						padding = append([]byte{suffix}, make([]byte, rate-n-2)...)
						padding = append(padding, 0x80)
					}
					want := append(bytes.Clone(before[:n]), padding...)
					if !bytes.Equal(out, want) || !bytes.Equal(backing, before) {
						t.Fatalf("padding = %x, want %x, or input modified", out, want)
					}
					out[0] ^= 0xff
					if !bytes.Equal(backing, before) {
						t.Fatal("output aliases tail")
					}
				})
			}
		}
	}
}

func TestSponge(t *testing.T) {
	// Sections 4-6: synthetic differential cases exercise every configuration,
	// including exact input rates and XOF output beyond two squeeze blocks.
	for _, tc := range []struct {
		name       string
		rate, size int
		suffix     byte
		oracle     func([]byte, int) []byte
	}{
		{"sha3-224", 144, 28, 6, func(b []byte, _ int) []byte { s := stdsha3.Sum224(b); return s[:] }},
		{"sha3-256", 136, 32, 6, func(b []byte, _ int) []byte { s := stdsha3.Sum256(b); return s[:] }},
		{"sha3-384", 104, 48, 6, func(b []byte, _ int) []byte { s := stdsha3.Sum384(b); return s[:] }},
		{"sha3-512", 72, 64, 6, func(b []byte, _ int) []byte { s := stdsha3.Sum512(b); return s[:] }},
		{"shake128", 168, 337, 31, stdsha3.SumSHAKE128},
		{"shake256", 136, 273, 31, stdsha3.SumSHAKE256},
	} {
		for _, n := range []int{0, 1, tc.rate - 1, tc.rate, tc.rate + 1, 2 * tc.rate} {
			t.Run(fmt.Sprintf("%s/input=%d", tc.name, n), func(t *testing.T) {
				defer failUnfinished(t)
				in := bytes.Repeat([]byte{0xa3}, n)
				want := tc.oracle(in, tc.size)
				if got := sponge(in, tc.rate, tc.suffix, tc.size); !bytes.Equal(got, want) {
					t.Fatalf("sponge = %x, want %x", got, want)
				}
			})
		}
	}
}

func TestSpongeInvalidParameters(t *testing.T) {
	// Exercise API contract. An unfinished panic must never satisfy rejection.
	for _, tc := range []struct {
		rate, size int
		suffix     byte
	}{{0, 32, 6}, {-8, 32, 6}, {8, 32, 6}, {135, 32, 6}, {200, 32, 6}, {136, -1, 6}, {136, 32, 0}, {136, 32, 0x80}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			defer func() {
				r := recover()
				if message, ok := r.(todo); ok {
					t.Fatalf("unfinished exercise: %s", message)
				}
				if r == nil {
					t.Fatal("invalid parameters did not panic")
				}
			}()
			sponge(nil, tc.rate, tc.suffix, tc.size)
		})
	}
}
