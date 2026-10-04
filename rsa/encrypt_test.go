// Test specifications: RFC 8017 / PKCS #1 v2.2 (November 2016) and Go 1.27.1.
// Individual cases cite sections; fixture provenance is in helpers_test.go.
package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestOAEPInterop(t *testing.T) {
	// Section 7.1; empty/max messages, labels and an independent MGF1 hash.
	for _, mgf := range []crypto.Hash{0, crypto.SHA256, crypto.SHA512} {
		for _, size := range []int{0, 17, 190} {
			for _, direction := range []string{"encrypt", "decrypt"} {
				t.Run(fmt.Sprintf("mgf_%d/size_%d/%s", mgf, size, direction), func(t *testing.T) {
					defer failUnfinished(t)
					key := exerciseFixture(t, 2048)
					oracle := standardFixture(t, 2048)
					before := keySnapshot(key)
					msg := bytes.Repeat([]byte{0x63}, size)
					label := []byte("rsa label")
					opts := &stdrsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: mgf, Label: label}
					var ct, got []byte
					var err error
					if direction == "encrypt" {
						ct, err = EncryptOAEPWithOptions(rand.Reader, &key.PublicKey, msg, opts)
						if err == nil {
							got, err = oracle.Decrypt(rand.Reader, ct, opts)
						}
					} else {
						ct, err = stdrsa.EncryptOAEPWithOptions(rand.Reader, &oracle.PublicKey, msg, opts)
						if err == nil {
							var d crypto.Decrypter = key
							got, err = d.Decrypt(rand.Reader, ct, opts)
						}
					}
					if err != nil || !bytes.Equal(got, msg) || len(ct) != key.Size() {
						t.Fatalf("OAEP interop: %v", err)
					}
					if !reflect.DeepEqual(before, keySnapshot(key)) || string(label) != "rsa label" || !bytes.Equal(msg, bytes.Repeat([]byte{0x63}, size)) || opts.Hash != crypto.SHA256 || opts.MGFHash != mgf {
						t.Fatal("input mutated")
					}
				})
			}
		}
	}
}

func TestOAEPHashAPI(t *testing.T) {
	// Section 7.1 and legacy hash.Hash API: same hash for OAEP and MGF1.
	for _, direction := range []string{"encrypt", "decrypt"} {
		t.Run(direction, func(t *testing.T) {
			defer failUnfinished(t)
			key := exerciseFixture(t, 2048)
			oracle := standardFixture(t, 2048)
			msg := []byte("hash.Hash API")
			var ct, got []byte
			var err error
			if direction == "encrypt" {
				ct, err = EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, msg, nil)
				if err == nil {
					got, err = stdrsa.DecryptOAEP(sha256.New(), rand.Reader, oracle, ct, nil)
				}
			} else {
				ct, err = stdrsa.EncryptOAEP(sha256.New(), rand.Reader, &oracle.PublicKey, msg, nil)
				if err == nil {
					got, err = DecryptOAEP(sha256.New(), rand.Reader, key, ct, nil)
				}
			}
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("OAEP hash API: %v", err)
			}
		})
	}
}

func TestOAEPRejection(t *testing.T) {
	// Section 7.1.2 decryption errors must not expose padding/label failures.
	for _, bad := range []string{"label", "mgf", "short", "range", "padding"} {
		t.Run(bad, func(t *testing.T) {
			defer failUnfinished(t)
			key := exerciseFixture(t, 2048)
			opts := &OAEPOptions{Hash: crypto.SHA256, Label: []byte("label")}
			ct, err := stdrsa.EncryptOAEPWithOptions(rand.Reader, &key.PublicKey, []byte("message"), opts)
			if err != nil {
				t.Fatal(err)
			}
			switch bad {
			case "label":
				opts.Label = []byte("wrong")
			case "mgf":
				opts.MGFHash = crypto.SHA512
			case "short":
				ct = ct[1:]
			case "range":
				ct = key.N.FillBytes(make([]byte, key.Size()))
			case "padding":
				ct = make([]byte, key.Size())
			}
			got, err := key.Decrypt(rand.Reader, ct, opts)
			if got != nil || !errors.Is(err, ErrDecryption) {
				t.Fatalf("decryption: %x, %v", got, err)
			}
		})
	}
	t.Run("too_long", func(t *testing.T) {
		defer failUnfinished(t)
		got, err := EncryptOAEPWithOptions(rand.Reader, &exerciseFixture(t, 2048).PublicKey, make([]byte, 191), &OAEPOptions{Hash: crypto.SHA256})
		if got != nil || !errors.Is(err, ErrMessageTooLong) {
			t.Fatalf("length boundary: %x, %v", got, err)
		}
	})
}

func TestPKCS1v15EncryptionInterop(t *testing.T) {
	// Section 7.2; nil DecrypterOpts and zero SessionKeyLen select v1.5.
	for _, direction := range []string{"encrypt", "decrypt_nil", "decrypt_options"} {
		t.Run(direction, func(t *testing.T) {
			defer failUnfinished(t)
			key := exerciseFixture(t, 2048)
			oracle := standardFixture(t, 2048)
			msg := []byte("legacy encryption")
			var ct, got []byte
			var err error
			if direction == "encrypt" {
				ct, err = EncryptPKCS1v15(rand.Reader, &key.PublicKey, msg)
				if err == nil {
					got, err = stdrsa.DecryptPKCS1v15(nil, oracle, ct)
				}
			} else {
				ct, err = stdrsa.EncryptPKCS1v15(rand.Reader, &oracle.PublicKey, msg)
				var opts crypto.DecrypterOpts
				if direction == "decrypt_options" {
					opts = &stdrsa.PKCS1v15DecryptOptions{}
				}
				if err == nil {
					var d crypto.Decrypter = key
					got, err = d.Decrypt(rand.Reader, ct, opts)
				}
			}
			if err != nil || !bytes.Equal(got, msg) || len(ct) != key.Size() {
				t.Fatalf("v1.5 encryption: %v", err)
			}
		})
	}
}

func TestSessionKeyFallback(t *testing.T) {
	// RFC 8017 7.2.2 notes + Go SessionKeyLen contract; pre-randomized fallback
	// remains unchanged on invalid padding or a wrong decoded key length.
	for _, mode := range []string{"valid", "padding", "wrong_length"} {
		for _, api := range []string{"buffer", "interface"} {
			t.Run(mode+"/"+api, func(t *testing.T) {
				defer failUnfinished(t)
				key := exerciseFixture(t, 2048)
				message := bytes.Repeat([]byte{0x42}, 16)
				if mode == "wrong_length" {
					message = message[:15]
				}
				ct, err := stdrsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, message)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "padding" {
					ct = make([]byte, key.Size())
				}
				fallback := bytes.Repeat([]byte{0xa5}, 16)
				got := bytes.Clone(fallback)
				if api == "buffer" {
					err = DecryptPKCS1v15SessionKey(rand.Reader, key, ct, got)
				} else {
					got, err = key.Decrypt(bytes.NewReader(fallback), ct, &stdrsa.PKCS1v15DecryptOptions{SessionKeyLen: 16})
				}
				want := fallback
				if mode == "valid" {
					want = message
				}
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("session key = %x, %v", got, err)
				}
			})
		}
	}
}
