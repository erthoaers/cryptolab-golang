// Test specifications: RFC 8017 / PKCS #1 v2.2 (November 2016) and Go 1.27.1.
// Individual cases cite sections; fixture provenance is in helpers_test.go.
package rsa

import (
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func TestVectorFixtures(t *testing.T) {
	// Fixture validation only: no exercise function is called. RFC 8017 sections
	// 3.1-3.2 and 5.1-5.2; locally constructed numbers, not conformance vectors.
	key := toyKey()
	if 61*53 != key.N.Int64() || 17*413%780 != 1 ||
		413%60 != key.Precomputed.Dp.Int64() || 413%52 != key.Precomputed.Dq.Int64() || 53*38%61 != 1 {
		t.Fatal("inconsistent toy key")
	}
	for _, row := range answers {
		if smallPower(row.x, 17, 3233) != row.public || smallPower(row.x, 413, 3233) != row.private {
			t.Fatalf("incorrect fixture for %d", row.x)
		}
		if smallPower(row.public, 413, 3233) != row.x || smallPower(row.private, 17, 3233) != row.x {
			t.Fatalf("fixture does not invert for %d", row.x)
		}
	}
}

func TestSchemeVectorFixtures(t *testing.T) {
	// Data validation only, RFC 8017 sections 3 and 8.1; 2049 bits exercises
	// emLen < signature length in PSS because emBits = modBits - 1.
	for _, bits := range []int{2048, 2049} {
		k := standardFixture(t, bits)
		sum := sha256.Sum256([]byte("fixture check"))
		sig, err := stdrsa.SignPSS(rand.Reader, k, crypto.SHA256, sum[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := stdrsa.VerifyPSS(&k.PublicKey, crypto.SHA256, sum[:], sig, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPublicContract(t *testing.T) {
	// Go Signer.Public, rsa.PublicKey and x509.MarshalPKIXPublicKey contracts.
	key := toyKey()
	var signer crypto.Signer = key
	var decrypter crypto.Decrypter = key
	pub, ok := signer.Public().(*stdrsa.PublicKey)
	if !ok || pub != &key.PublicKey || pub != decrypter.Public() {
		t.Fatal("Public must expose the embedded standard public key")
	}
	if pub.Size() != 2 || !pub.Equal(&PublicKey{N: big.NewInt(3233), E: 17}) {
		t.Fatal("public size/equality mismatch")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil || !pub.Equal(parsed) {
		t.Fatalf("public x509 round trip: %v", err)
	}
}

func TestPrivateEqual(t *testing.T) {
	// Go rsa.PrivateKey.Equal contract: compare material, ignore CRT cache.
	a, b := toyKey(), toyKey()
	b.Precomputed = PrecomputedValues{}
	if !a.Equal(b) || a.Equal(&stdrsa.PrivateKey{}) || a.Equal((*PrivateKey)(nil)) {
		t.Fatal("private equality/type mismatch")
	}
	for _, mutate := range []func(*PrivateKey){
		func(k *PrivateKey) { k.E++ }, func(k *PrivateKey) { k.N.Add(k.N, big.NewInt(1)) },
		func(k *PrivateKey) { k.D.Add(k.D, big.NewInt(1)) },
		func(k *PrivateKey) { k.Primes[0], k.Primes[1] = k.Primes[1], k.Primes[0] },
	} {
		changed := toyKey()
		mutate(changed)
		if a.Equal(changed) {
			t.Fatal("changed key compares equal")
		}
	}
}

func TestInvalidInterfaceOptions(t *testing.T) {
	// Local nil-option error policy; Go Decrypter rejects unknown option types.
	k := toyKey()
	for _, opts := range []crypto.SignerOpts{nil, (*stdrsa.PSSOptions)(nil)} {
		got, err := k.Sign(rand.Reader, nil, opts)
		if got != nil || !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("Sign: %x, %v", got, err)
		}
	}
	for _, opts := range []crypto.DecrypterOpts{struct{}{}, crypto.SHA256, (*stdrsa.OAEPOptions)(nil), (*stdrsa.PKCS1v15DecryptOptions)(nil)} {
		got, err := k.Decrypt(rand.Reader, nil, opts)
		if got != nil || !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("Decrypt: %x, %v", got, err)
		}
	}
}

func TestNewPrivateKey(t *testing.T) {
	// RFC 8017 sections 3.1-3.2; local toy key, both factor orders.
	for _, swapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("swapped_%t", swapped), func(t *testing.T) {
			defer failUnfinished(t)
			want := toyKey()
			if swapped {
				want.Primes[0], want.Primes[1] = want.Primes[1], want.Primes[0]
				want.Precomputed.Dp, want.Precomputed.Dq = want.Precomputed.Dq, want.Precomputed.Dp
				want.Precomputed.Qinv.SetInt64(20)
			}
			p, q := new(big.Int).Set(want.Primes[0]), new(big.Int).Set(want.Primes[1])
			got, err := NewPrivateKey(p, q, 17)
			if err != nil || got == nil {
				t.Fatalf("NewPrivateKey = %v, %v", got, err)
			}
			if !reflect.DeepEqual(keySnapshot(got), keySnapshot(want)) {
				t.Fatalf("key = %v, want %v", keySnapshot(got), keySnapshot(want))
			}
			requireInt(t, p, want.Primes[0])
			requireInt(t, q, want.Primes[1])
			p.SetInt64(0)
			q.SetInt64(0)
			if !reflect.DeepEqual(keySnapshot(got), keySnapshot(want)) {
				t.Fatal("key aliases input primes")
			}
		})
	}
}

func TestNewPrivateKeyErrors(t *testing.T) {
	// RFC 8017 section 3 valid-key conditions plus the local constructor contract.
	cases := []struct {
		name string
		p, q *big.Int
		e    int
	}{
		{"nil_p", nil, big.NewInt(53), 17}, {"nil_q", big.NewInt(61), nil, 17},
		{"zero", big.NewInt(0), big.NewInt(53), 17}, {"one", big.NewInt(1), big.NewInt(53), 17},
		{"negative", big.NewInt(-61), big.NewInt(53), 17}, {"two", big.NewInt(2), big.NewInt(53), 17},
		{"even", big.NewInt(60), big.NewInt(53), 17}, {"composite_p", big.NewInt(9), big.NewInt(53), 17},
		{"composite_q", big.NewInt(61), big.NewInt(9), 17}, {"equal", big.NewInt(61), big.NewInt(61), 17},
		{"negative_e", big.NewInt(61), big.NewInt(53), -17}, {"zero_e", big.NewInt(61), big.NewInt(53), 0},
		{"one_e", big.NewInt(61), big.NewInt(53), 1}, {"even_e", big.NewInt(61), big.NewInt(53), 2},
		{"not_coprime", big.NewInt(61), big.NewInt(53), 15}, {"e_equals_n", big.NewInt(61), big.NewInt(53), 3233},
		{"e_above_n", big.NewInt(61), big.NewInt(53), 3239},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			p, q := tc.p.String(), tc.q.String()
			got, err := NewPrivateKey(tc.p, tc.q, tc.e)
			if got != nil || !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("got %v, %v; want nil, ErrInvalidKey", got, err)
			}
			if tc.p.String() != p || tc.q.String() != q {
				t.Fatal("input changed on failure")
			}
		})
	}
}

func TestKeyFieldOwnership(t *testing.T) {
	// Local ownership contract: mutating one big.Int must not change other fields.
	defer failUnfinished(t)
	for i := range keyFields(toyKey()) {
		key, err := NewPrivateKey(big.NewInt(61), big.NewInt(53), 17)
		if err != nil || key == nil {
			t.Fatalf("NewPrivateKey = %v, %v", key, err)
		}
		fields := keyFields(key)
		before := keySnapshot(key)
		for _, x := range fields {
			if x == nil {
				t.Fatal("nil key field")
			}
		}
		fields[i].SetInt64(-1)
		for j, x := range fields {
			if i != j && x.String() != before[j+1] {
				t.Fatalf("fields %d and %d alias", i, j)
			}
		}
	}
}

func TestValidate(t *testing.T) {
	// RFC 8017 section 3; local key mutations, independent standard key fixture.
	cases := []struct {
		name   string
		mutate func(*PrivateKey)
		valid  bool
	}{
		{"valid", func(k *PrivateKey) {}, true},
		{"without_cache", func(k *PrivateKey) { k.Precomputed = PrecomputedValues{} }, true},
		{"wrong_n", func(k *PrivateKey) { k.N.Add(k.N, big.NewInt(2)) }, false},
		{"wrong_d", func(k *PrivateKey) { k.D.Add(k.D, big.NewInt(1)) }, false},
		{"even_e", func(k *PrivateKey) { k.E = 2 }, false},
		{"no_primes", func(k *PrivateKey) { k.Primes = nil }, false},
		{"nil_prime", func(k *PrivateKey) { k.Primes[0] = nil }, false},
		{"nil_n", func(k *PrivateKey) { k.N = nil }, false},
		{"nil_d", func(k *PrivateKey) { k.D = nil }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer failUnfinished(t)
			k := exerciseFixture(t, 2048)
			tc.mutate(k)
			err := k.Validate()
			if tc.valid && err != nil || !tc.valid && !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("Validate = %v, valid = %t", err, tc.valid)
			}
		})
	}
}

func TestPrecompute(t *testing.T) {
	// RFC 8017 section 3.2; compare with independently precomputed toy data.
	defer failUnfinished(t)
	k := toyKey()
	want := keySnapshot(k)
	k.Precomputed = PrecomputedValues{}
	k.Precompute()
	k.Precompute()
	if !reflect.DeepEqual(keySnapshot(k), want) {
		t.Fatal("wrong CRT values or key mutation")
	}
	k.Precomputed.Dp.SetInt64(0)
	if k.D.Int64() != 413 || k.Primes[0].Int64() != 61 {
		t.Fatal("cache aliases source material")
	}
}

func TestGenerateKey(t *testing.T) {
	// API/relationship smoke test only, NOT FIPS key-generation conformance.
	// FIPS 186-5 (2023), Appendix A.1; SP 800-56B Rev. 2 (2019), section 6.
	defer failUnfinished(t)
	key, err := GenerateKey(rand.Reader, 2048)
	if err != nil || key == nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key.N.BitLen() != 2048 || key.E != 65537 || len(key.Primes) != 2 {
		t.Fatal("wrong key parameters")
	}
	oracle := &stdrsa.PrivateKey{PublicKey: key.PublicKey, D: key.D, Primes: key.Primes}
	if err := oracle.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRandomReaderErrors(t *testing.T) {
	// Local io.Reader contract; unlike Go 1.27 global-randomness policy, the
	// exercise consumes its explicit reader for probabilistic operations.
	for _, op := range []string{"oaep", "pss", "session_key", "generate"} {
		t.Run(op, func(t *testing.T) {
			defer failUnfinished(t)
			key := exerciseFixture(t, 2048)
			sum := sha256.Sum256(nil)
			var err error
			switch op {
			case "oaep":
				_, err = EncryptOAEP(sha256.New(), failedReader{}, &key.PublicKey, nil, nil)
			case "pss":
				_, err = SignPSS(failedReader{}, key, crypto.SHA256, sum[:], nil)
			case "session_key":
				_, err = key.Decrypt(failedReader{}, make([]byte, key.Size()), &PKCS1v15DecryptOptions{SessionKeyLen: 16})
			case "generate":
				_, err = GenerateKey(failedReader{}, 2048)
			}
			if !errors.Is(err, errEntropy) {
				t.Fatalf("reader error lost: %v", err)
			}
		})
	}
}
