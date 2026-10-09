// Specifications: RFC 8017 / PKCS #1 v2.2 (November 2016), sections 5 and 7-9.
// Keys are the public test-only fixtures documented in helpers_test.go;
// messages, salts, fallback keys and factors below are local test data.
// Explicit-reader consumption, nil-reader errors and error propagation follow
// the local RSA-11c contract, not RFC requirements or Go 1.27's entropy policy.
package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"reflect"
	"testing"
)

type blindingSchemeCase struct {
	name     string
	prefix   []byte
	fallback []byte
	run      func(io.Reader, *PrivateKey) ([]byte, error)
	verify   func(*testing.T, []byte)
}

func blindingSchemeCases(t *testing.T) []blindingSchemeCase {
	t.Helper()
	oracle := standardFixture(t, 2048)
	message := bytes.Repeat([]byte{0x42}, 16)
	label := []byte("blinding integration")
	digest := sha256.Sum256(message)
	fallback := bytes.Repeat([]byte{0xa5}, len(message))
	salt := bytes.Repeat([]byte{0x3c}, sha256.Size)
	oaepOpts := &OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA512, Label: label}
	pssOpts := &PSSOptions{Hash: crypto.SHA256, SaltLength: PSSSaltLengthEqualsHash}
	oaep, err := stdrsa.EncryptOAEP(sha256.New(), rand.Reader, &oracle.PublicKey, message, label)
	if err != nil {
		t.Fatal(err)
	}
	mixedOAEP, err := stdrsa.EncryptOAEPWithOptions(rand.Reader, &oracle.PublicKey, message, oaepOpts)
	if err != nil {
		t.Fatal(err)
	}
	pkcs, err := stdrsa.EncryptPKCS1v15(rand.Reader, &oracle.PublicKey, message)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := stdrsa.SignPKCS1v15(nil, oracle, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	equalTo := func(want []byte) func(*testing.T, []byte) {
		return func(t *testing.T, got []byte) {
			t.Helper()
			if !bytes.Equal(got, want) {
				t.Fatal("blinded result differs from the independent expected result")
			}
		}
	}
	verifyPSS := func(t *testing.T, sig []byte) {
		t.Helper()
		if err := stdrsa.VerifyPSS(&oracle.PublicKey, crypto.SHA256, digest[:], sig, pssOpts); err != nil {
			t.Fatalf("standard-library PSS verification: %v", err)
		}
	}
	return []blindingSchemeCase{
		{name: "oaep", verify: equalTo(message), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			return DecryptOAEP(sha256.New(), random, key, oaep, label)
		}},
		{name: "oaep_interface_mgf", verify: equalTo(message), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			var decrypter crypto.Decrypter = key
			return decrypter.Decrypt(random, mixedOAEP, oaepOpts)
		}},
		{name: "pkcs1v15", verify: equalTo(message), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			return DecryptPKCS1v15(random, key, pkcs)
		}},
		{name: "pkcs1v15_interface_nil", verify: equalTo(message), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			var decrypter crypto.Decrypter = key
			return decrypter.Decrypt(random, pkcs, nil)
		}},
		{name: "pkcs1v15_interface_options", verify: equalTo(message), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			var decrypter crypto.Decrypter = key
			return decrypter.Decrypt(random, pkcs, &PKCS1v15DecryptOptions{})
		}},
		{name: "session_buffer", fallback: fallback, verify: equalTo(message), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			out := bytes.Clone(fallback)
			err := DecryptPKCS1v15SessionKey(random, key, pkcs, out)
			return out, err
		}},
		{name: "session_interface", prefix: fallback, verify: equalTo(message), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			var decrypter crypto.Decrypter = key
			return decrypter.Decrypt(random, pkcs, &PKCS1v15DecryptOptions{SessionKeyLen: len(fallback)})
		}},
		{name: "pkcs1v15_sign", verify: equalTo(signature), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			return SignPKCS1v15(random, key, crypto.SHA256, digest[:])
		}},
		{name: "pkcs1v15_sign_interface", verify: equalTo(signature), run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			var signer crypto.Signer = key
			return signer.Sign(random, digest[:], crypto.SHA256)
		}},
		{name: "pss_sign", prefix: salt, verify: verifyPSS, run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			return SignPSS(random, key, crypto.SHA256, digest[:], pssOpts)
		}},
		{name: "pss_sign_interface", prefix: salt, verify: verifyPSS, run: func(random io.Reader, key *PrivateKey) ([]byte, error) {
			var signer crypto.Signer = key
			return signer.Sign(random, digest[:], pssOpts)
		}},
	}
}

func TestSchemeBlindingInterop(t *testing.T) {
	// RFC 8017 sections 7-9: blinding preserves plaintext/signature semantics.
	// Both factors are invertible for the fixed key. PSS uses a fixed salt so
	// equality across factors also checks the salt-before-blinding read order.
	for _, scheme := range blindingSchemeCases(t) {
		for _, path := range []string{"crt", "direct"} {
			t.Run(scheme.name+"/"+path, func(t *testing.T) {
				defer failUnfinished(t)
				key := exerciseFixture(t, 2048)
				if path == "direct" {
					key.Precomputed = PrecomputedValues{}
				}
				before := keySnapshot(key)
				var previous []byte
				for _, factor := range []byte{2, 3} {
					input := append(bytes.Clone(scheme.prefix), make([]byte, key.Size())...)
					input[len(input)-1] = factor
					random := bytes.NewReader(append(input, 0xa7))
					got, err := scheme.run(random, key)
					if err != nil {
						t.Fatalf("factor %d: %v", factor, err)
					}
					scheme.verify(t, got)
					if random.Len() != 1 {
						t.Fatalf("factor %d: %d unread bytes, want only the sentinel", factor, random.Len())
					}
					if previous != nil && !bytes.Equal(got, previous) {
						t.Fatal("result changed with the blinding factor")
					}
					previous = bytes.Clone(got)
					if !reflect.DeepEqual(before, keySnapshot(key)) {
						t.Fatal("private key mutated")
					}
				}
			})
		}
	}
}

func TestSchemeBlindingReaderErrors(t *testing.T) {
	// Local RSA-11c entropy contract: a valid operation must not silently use
	// unblinded exponentiation, mask entropy errors, return output or panic.
	for _, scheme := range blindingSchemeCases(t) {
		key := exerciseFixture(t, 2048)
		cases := []struct {
			name   string
			random io.Reader
			want   error
		}{
			{"nil", nil, ErrInvalidOptions},
			{"blinding_error", io.MultiReader(bytes.NewReader(scheme.prefix), failedReader{}), errEntropy},
			{"blinding_eof", bytes.NewReader(scheme.prefix), io.EOF},
			{"blinding_short", bytes.NewReader(append(bytes.Clone(scheme.prefix), make([]byte, key.Size()-1)...)), io.ErrUnexpectedEOF},
			{"blinding_error_after_rejection", io.MultiReader(bytes.NewReader(append(bytes.Clone(scheme.prefix), make([]byte, key.Size())...)), failedReader{}), errEntropy},
		}
		if len(scheme.prefix) > 0 {
			cases = append(cases, struct {
				name   string
				random io.Reader
				want   error
			}{"prefix_error", failedReader{}, errEntropy})
		}
		for _, tc := range cases {
			t.Run(scheme.name+"/"+tc.name, func(t *testing.T) {
				// Turn a nil-reader panic into a failing case so the rest of the
				// integration suite still runs and reports independent failures.
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("operation panicked instead of returning %v: %v", tc.want, p)
					}
				}()
				before := keySnapshot(key)
				got, err := scheme.run(tc.random, key)
				if !errors.Is(err, tc.want) {
					t.Errorf("error = %v, want %v", err, tc.want)
				}
				if scheme.fallback != nil {
					if !bytes.Equal(got, scheme.fallback) {
						t.Error("caller-provided session key changed on failure")
					}
				} else if got != nil {
					t.Error("operation returned output on failure")
				}
				if !reflect.DeepEqual(before, keySnapshot(key)) {
					t.Error("private key mutated on failure")
				}
			})
		}
	}
}

func TestSchemeBlindingCiphertextRejection(t *testing.T) {
	// RFC 8017 (2016), 7.1.2 steps 1/2.b and 7.2.2 steps 1/2.b: invalid
	// public length/range returns ErrDecryption. The local contract rejects
	// these before blinding; SessionKeyLen still consumes its fallback first.
	for _, api := range []string{"oaep", "oaep_interface", "pkcs1v15", "pkcs1v15_interface_nil", "pkcs1v15_interface_options", "session_buffer", "session_interface"} {
		for _, invalid := range []string{"short", "long", "equal_n", "above_n"} {
			t.Run(api+"/"+invalid, func(t *testing.T) {
				defer failUnfinished(t)
				key := exerciseFixture(t, 2048)
				var ct []byte
				switch invalid {
				case "short":
					ct = make([]byte, key.Size()-1)
				case "long":
					ct = make([]byte, key.Size()+1)
				case "equal_n":
					ct = key.N.FillBytes(make([]byte, key.Size()))
				case "above_n":
					ct = new(big.Int).Add(key.N, big.NewInt(1)).FillBytes(make([]byte, key.Size()))
				}
				fallback := bytes.Repeat([]byte{0xa5}, 16)
				reader := &blindingCountingReader{reader: failedReader{}}
				var got []byte
				var err error
				switch api {
				case "oaep":
					got, err = DecryptOAEP(sha256.New(), reader, key, ct, nil)
				case "oaep_interface":
					got, err = key.Decrypt(reader, ct, &OAEPOptions{Hash: crypto.SHA256})
				case "pkcs1v15":
					got, err = DecryptPKCS1v15(reader, key, ct)
				case "pkcs1v15_interface_nil":
					got, err = key.Decrypt(reader, ct, nil)
				case "pkcs1v15_interface_options":
					got, err = key.Decrypt(reader, ct, &PKCS1v15DecryptOptions{})
				case "session_buffer":
					out := bytes.Clone(fallback)
					err = DecryptPKCS1v15SessionKey(reader, key, ct, out)
					if !bytes.Equal(out, fallback) {
						t.Error("session key changed on invalid ciphertext")
					}
				case "session_interface":
					random := io.MultiReader(bytes.NewReader(fallback), reader)
					got, err = key.Decrypt(random, ct, &PKCS1v15DecryptOptions{SessionKeyLen: len(fallback)})
				}
				if got != nil || !errors.Is(err, ErrDecryption) {
					t.Fatalf("invalid ciphertext: got %x, %v; want nil, ErrDecryption", got, err)
				}
				if reader.calls != 0 {
					t.Fatalf("invalid ciphertext read blinding randomness %d times", reader.calls)
				}
			})
		}
	}
}
