// Test specifications: RFC 8017 / PKCS #1 v2.2 (November 2016) and Go 1.27.1.
// Individual cases cite sections; fixture provenance is in helpers_test.go.
package rsa

import (
	"bytes"
	"crypto"
	stdrsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
)

// Specification: RFC 8017, PKCS #1 v2.2 (November 2016), sections 3-5.
// https://www.rfc-editor.org/rfc/rfc8017.html
// All numbers below are locally constructed educational fixtures, NOT official
// RFC/NIST vectors. Small fixed answers were checked with Python integer pow;
// TestVectorFixtures rechecks them with repeated integer multiplication.
// math/big.Exp provides a separate oracle for multiword differential tests.

func failUnfinished(t *testing.T) {
	t.Helper()
	if recovered := recover(); recovered != nil {
		if message, ok := recovered.(todo); ok {
			t.Fatalf("unfinished exercise: %s", message)
		}
		panic(recovered)
	}
}

// p=61, q=53, lambda(n)=780; d is the least positive inverse of 17 modulo 780.
// The familiar d=2753 is also valid, but is not the constructor's canonical d.
func toyKey() *PrivateKey {
	return &PrivateKey{
		PublicKey:   PublicKey{N: big.NewInt(3233), E: 17},
		D:           big.NewInt(413),
		Primes:      []*big.Int{big.NewInt(61), big.NewInt(53)},
		Precomputed: PrecomputedValues{Dp: big.NewInt(53), Dq: big.NewInt(49), Qinv: big.NewInt(38)},
	}
}

var answers = []struct{ x, public, private int64 }{
	{0, 0, 0}, {1, 1, 1}, {2, 1752, 1027}, {42, 2557, 3065},
	{53, 1802, 3074}, {61, 610, 2806}, {65, 2790, 588},
	{123, 855, 2746}, {3232, 3232, 3232},
}

// Safe only for these tiny fixtures: every intermediate product fits int64.
func smallPower(x, e, n int64) int64 {
	y := int64(1)
	for i := int64(0); i < e; i++ {
		y = y * x % n
	}
	return y
}

func keyFields(key *PrivateKey) []*big.Int {
	return []*big.Int{key.N, key.D, key.Primes[0], key.Primes[1], key.Precomputed.Dp, key.Precomputed.Dq, key.Precomputed.Qinv}
}

func keySnapshot(key *PrivateKey) []string {
	values := []string{fmt.Sprint(key.E)}
	for _, x := range keyFields(key) {
		values = append(values, x.String())
	}
	return values
}

func requireInt(t *testing.T, got, want *big.Int) {
	t.Helper()
	if got == nil || got.Cmp(want) != 0 {
		t.Fatalf("integer = %v, want %v", got, want)
	}
}

// Contracts: Go 1.27.1 crypto.Signer / Decrypter and crypto/rsa option semantics.
// https://pkg.go.dev/crypto@go1.27.1#Signer
// https://pkg.go.dev/crypto/rsa@go1.27.1
// Algorithm specification: RFC 8017 / PKCS #1 v2.2 (November 2016), sections
// 3-5, 7-9 and Appendix B.2.1. These are local differential/contract cases,
// not official RFC or NIST conformance vectors. testdata/test-only-*.pem were
// generated once with Go 1.27.1 crypto/rsa.GenerateKey, e=65537, on 2026-10-03.
// They are public test fixtures and MUST NOT be used as real private keys.
// Standard crypto operations below are test oracles only.

func standardFixture(t *testing.T, bits int) *stdrsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("testdata/test-only-%d.pem", bits))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("invalid fixture PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != bits || key.E != 65537 || len(key.Primes) != 2 {
		t.Fatal("incorrect fixture parameters")
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	return key
}

// Deep-copy fixture data without using any algorithm under test. This avoids
// an unfinished constructor masking failures in later scheme exercises.
func exerciseFixture(t *testing.T, bits int) *PrivateKey {
	t.Helper()
	k := standardFixture(t, bits)
	clone := func(x *big.Int) *big.Int { return new(big.Int).Set(x) }
	return &PrivateKey{
		PublicKey: PublicKey{N: clone(k.N), E: k.E}, D: clone(k.D),
		Primes:      []*big.Int{clone(k.Primes[0]), clone(k.Primes[1])},
		Precomputed: PrecomputedValues{clone(k.Precomputed.Dp), clone(k.Precomputed.Dq), clone(k.Precomputed.Qinv)},
	}
}

type hashOpts struct{ crypto.Hash }

var errEntropy = errors.New("test entropy unavailable")

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errEntropy }
