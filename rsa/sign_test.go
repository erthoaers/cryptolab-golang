// Test specifications: RFC 8017 / PKCS #1 v2.2 (November 2016) and Go 1.27.1.
// Individual cases cite sections; fixture provenance is in helpers_test.go.
package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// Specification: RFC 8017 / PKCS #1 v2.2 (November 2016), sections 7-9.
// API behavior: Go 1.27.1 crypto/rsa, https://pkg.go.dev/crypto/rsa@go1.27.1.
// All cases use locally generated messages and test-only keys (provenance in
// helpers_test.go). Standard-library functions are independent test oracles;
// randomized outputs are verified/decrypted, never compared byte-for-byte.

func TestPSSInterop(t *testing.T) {
	// Sections 8.1 and 9.1; check both directions and emLen != signature size.
	for _, bits := range []int{2048, 2049} {
		for _, salt := range []int{PSSSaltLengthAuto, PSSSaltLengthEqualsHash, 8} {
			for _, direction := range []string{"sign", "verify"} {
				t.Run(fmt.Sprintf("%d/salt_%d/%s", bits, salt, direction), func(t *testing.T) {
					defer failUnfinished(t)
					key := exerciseFixture(t, bits)
					oracle := standardFixture(t, bits)
					before := keySnapshot(key)
					digest := sha256.Sum256([]byte("RSA PSS interoperability"))
					original := digest
					opts := &stdrsa.PSSOptions{Hash: crypto.SHA256, SaltLength: salt}
					saved := *opts
					var sig []byte
					var err error
					if direction == "sign" {
						var signer crypto.Signer = key
						sig, err = signer.Sign(rand.Reader, digest[:], opts)
						if err == nil {
							err = stdrsa.VerifyPSS(&oracle.PublicKey, crypto.SHA256, digest[:], sig, opts)
						}
					} else {
						sig, err = stdrsa.SignPSS(rand.Reader, oracle, crypto.SHA256, digest[:], opts)
						if err == nil {
							err = VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, opts)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if len(sig) != key.Size() || digest != original || *opts != saved || !reflect.DeepEqual(before, keySnapshot(key)) {
						t.Fatal("size or input ownership failure")
					}
				})
			}
		}
	}
}

func TestPSSOptions(t *testing.T) {
	// Go SignPSS Hash override, nil defaults; VerifyPSS ignores opts.Hash.
	t.Run("hash_override", func(t *testing.T) {
		defer failUnfinished(t)
		key := exerciseFixture(t, 2048)
		sum := sha256.Sum256([]byte("override"))
		sig, err := SignPSS(rand.Reader, key, crypto.SHA512, sum[:], &PSSOptions{Hash: crypto.SHA256, SaltLength: PSSSaltLengthEqualsHash})
		if err != nil {
			t.Fatal(err)
		}
		if err := stdrsa.VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], sig, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("nil_defaults", func(t *testing.T) {
		defer failUnfinished(t)
		key := exerciseFixture(t, 2048)
		sum := sha256.Sum256(nil)
		sig, err := SignPSS(rand.Reader, key, crypto.SHA256, sum[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := stdrsa.VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], sig, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("verify_ignores_opts_hash", func(t *testing.T) {
		defer failUnfinished(t)
		key := standardFixture(t, 2048)
		sum := sha256.Sum256(nil)
		sig, err := stdrsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], sig, &PSSOptions{Hash: crypto.SHA512}); err != nil {
			t.Fatal(err)
		}
	})
	for _, name := range []string{"wrong_digest_size", "invalid_salt", "excessive_salt"} {
		t.Run(name, func(t *testing.T) {
			defer failUnfinished(t)
			sum := sha256.Sum256(nil)
			digest := sum[:]
			opts := &PSSOptions{SaltLength: PSSSaltLengthEqualsHash}
			switch name {
			case "wrong_digest_size":
				digest = digest[:31]
			case "invalid_salt":
				opts.SaltLength = -2
			case "excessive_salt":
				opts.SaltLength = 256
			}
			if sig, err := SignPSS(rand.Reader, exerciseFixture(t, 2048), crypto.SHA256, digest, opts); err == nil || sig != nil {
				t.Fatal("invalid signing parameters accepted")
			}
		})
	}
}

func TestSignatureRejection(t *testing.T) {
	// RFC 8017 8.1.2 / 8.2.2: modified digest/signature, wrong size and wrong salt.
	for _, scheme := range []string{"pss", "pkcs1v15"} {
		for _, bad := range []string{"digest", "signature", "short", "long", "range"} {
			t.Run(scheme+"/"+bad, func(t *testing.T) {
				defer failUnfinished(t)
				key := standardFixture(t, 2048)
				sum := sha256.Sum256([]byte("tampering"))
				var sig []byte
				var err error
				if scheme == "pss" {
					sig, err = stdrsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], nil)
				} else {
					sig, err = stdrsa.SignPKCS1v15(nil, key, crypto.SHA256, sum[:])
				}
				if err != nil {
					t.Fatal(err)
				}
				switch bad {
				case "digest":
					sum[0] ^= 1
				case "signature":
					sig[len(sig)-1] ^= 1
				case "short":
					sig = sig[1:]
				case "long":
					sig = append([]byte{0}, sig...)
				case "range":
					sig = key.N.FillBytes(make([]byte, key.Size()))
				}
				if scheme == "pss" {
					err = VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], sig, nil)
				} else {
					err = VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig)
				}
				if !errors.Is(err, ErrVerification) {
					t.Fatalf("tampered signature: %v", err)
				}
			})
		}
	}
	t.Run("pss_wrong_salt_length", func(t *testing.T) {
		defer failUnfinished(t)
		key := standardFixture(t, 2048)
		sum := sha256.Sum256(nil)
		sig, err := stdrsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], &stdrsa.PSSOptions{SaltLength: 8})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], sig, &PSSOptions{SaltLength: PSSSaltLengthEqualsHash}); !errors.Is(err, ErrVerification) {
			t.Fatalf("wrong salt length: %v", err)
		}
	})
}

func TestPKCS1v15SignatureInterop(t *testing.T) {
	// Sections 8.2 / 9.2; crypto.Hash(0) raw bytes and custom SignerOpts.
	for _, hashID := range []crypto.Hash{0, crypto.SHA256} {
		for _, direction := range []string{"sign", "verify"} {
			t.Run(fmt.Sprintf("hash_%d/%s", hashID, direction), func(t *testing.T) {
				defer failUnfinished(t)
				key := exerciseFixture(t, 2048)
				oracle := standardFixture(t, 2048)
				sum := sha256.Sum256([]byte("v1.5 signature"))
				digest := sum[:]
				if hashID == 0 {
					digest = []byte("raw bytes")
				}
				expected, err := stdrsa.SignPKCS1v15(nil, oracle, hashID, digest)
				if err != nil {
					t.Fatal(err)
				}
				if direction == "sign" {
					var signer crypto.Signer = key
					sig, err := signer.Sign(rand.Reader, digest, hashOpts{hashID})
					if err != nil || !bytes.Equal(sig, expected) {
						t.Fatalf("deterministic signature mismatch: %v", err)
					}
				} else if err := VerifyPKCS1v15(&key.PublicKey, hashID, digest, expected); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestSignerX509(t *testing.T) {
	// Go crypto.Signer integration through x509, with RFC 8017 PSS or v1.5.
	for _, alg := range []x509.SignatureAlgorithm{x509.SHA256WithRSAPSS, x509.SHA256WithRSA} {
		t.Run(alg.String(), func(t *testing.T) {
			defer failUnfinished(t)
			var signer crypto.Signer = exerciseFixture(t, 2048)
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "rsa.learning.invalid"}, SignatureAlgorithm: alg,
			}, signer)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := csr.CheckSignature(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
