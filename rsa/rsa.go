// Package rsa is a two-prime RSA learning scaffold following RFC 8017
// (PKCS #1 v2.2, November 2016), with Go crypto.Signer and crypto.Decrypter
// adapters. Encryption, signature schemes, and key generation remain TODO exercises.
// This math/big-based project is not a constant-time or production library.
package rsa

import (
	"crypto"
	stdrsa "crypto/rsa"
	"errors"
	"io"
	"math/big"
)

type todo string

// PublicKey reuses the standard public representation, including Size and
// Equal, so Public() is understood by crypto/x509 and standard verifiers.
// Only types, constants and errors are shared; no RSA operations are delegated.
type PublicKey = stdrsa.PublicKey

// PrivateKey holds the RFC 8017 section 3.2 two-prime key representations.
// Primes contains exactly p and q. Keep key material immutable after setup.
// The field layout follows crypto/rsa, but this is an independent private key.
type PrivateKey struct {
	PublicKey
	D           *big.Int
	Primes      []*big.Int
	Precomputed PrecomputedValues
}

// PrecomputedValues caches the section 3.2 CRT values for two primes only.
// Dp = d mod (p-1), Dq = d mod (q-1), Qinv = q^-1 mod p.
type PrecomputedValues struct {
	Dp, Dq, Qinv *big.Int
}

type PSSOptions = stdrsa.PSSOptions

type OAEPOptions = stdrsa.OAEPOptions

type PKCS1v15DecryptOptions = stdrsa.PKCS1v15DecryptOptions

const (
	PSSSaltLengthAuto       = stdrsa.PSSSaltLengthAuto
	PSSSaltLengthEqualsHash = stdrsa.PSSSaltLengthEqualsHash
)

var (
	ErrInvalidInteger           = errors.New("rsa: integer must be non-nil and nonnegative")
	ErrInvalidLength            = errors.New("rsa: length must be nonnegative")
	ErrIntegerTooLarge          = errors.New("rsa: integer too large")
	ErrInvalidKey               = errors.New("rsa: invalid key parameters")
	ErrRepresentativeOutOfRange = errors.New("rsa: representative out of range")
	ErrInvalidOptions           = errors.New("rsa: invalid options")
	ErrUnsupportedHash          = errors.New("rsa: unsupported hash")
	ErrDecryption               = stdrsa.ErrDecryption
	ErrVerification             = stdrsa.ErrVerification
	ErrMessageTooLong           = stdrsa.ErrMessageTooLong
)

var (
	_ crypto.Signer    = (*PrivateKey)(nil)
	_ crypto.Decrypter = (*PrivateKey)(nil)
)

// NewPrivateKey derives a key from supplied distinct odd primes, not randomness.
// Reject nil, nonpositive, even, equal, or composite factors; require 3 <= e < n
// and gcd(e, lcm(p-1,q-1)) = 1. Return nil, ErrInvalidKey for invalid parameters.
// big.Int.ProbablyPrime(32) is sufficient for this learning exercise.
// Choose the least positive inverse d modulo lcm(p-1,q-1); derive Precomputed.Dp, Dq, Qinv and store p, q in Primes.
// Own every big.Int field independently, without mutating or aliasing p or q.
func NewPrivateKey(p, q *big.Int, e int) (*PrivateKey, error) {
	if p == nil || q == nil || p.Sign() <= 0 || q.Sign() <= 0 || p.Cmp(q) == 0 || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) || p.Bit(0) == 0 || q.Bit(0) == 0 {
		return nil, ErrInvalidKey
	}
	n := new(big.Int).Mul(p, q)
	if e < 3 || big.NewInt(int64(e)).Cmp(n) >= 0 {
		return nil, ErrInvalidKey
	}

	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	lcm := new(big.Int).Div(new(big.Int).Mul(pMinus1, qMinus1), new(big.Int).GCD(nil, nil, pMinus1, qMinus1))
	d := new(big.Int).ModInverse(big.NewInt(int64(e)), lcm)
	if d == nil {
		return nil, ErrInvalidKey
	}

	priv := &PrivateKey{
		PublicKey: PublicKey{
			N: n,
			E: e,
		},
		D:      d,
		Primes: []*big.Int{new(big.Int).Set(p), new(big.Int).Set(q)},
	}
	priv.Precompute()
	return priv, nil
}

// GenerateKey is the planned random two-prime key-generation entry point.
// The learning contract uses random (normally crypto/rand.Reader), e=65537,
// and rejects bits < 1024. It must return an exactly bits-wide modulus and
// propagate reader errors. Go 1.27 normally ignores its reader argument;
// that global randomness policy is intentionally not reproduced here.
// Study FIPS 186-5 Appendix A.1 and SP 800-56B Rev. 2 section 6 before filling
// this TODO. The presence of this API does not claim a FIPS-approved generator.
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	panic(todo("TODO RSA-10: generate and validate a two-prime key; FIPS 186-5 Appendix A.1"))
}

// Public returns the embedded public key, as crypto/rsa.PrivateKey.Public does.
// This shares N with the private key; callers must treat it as read-only.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Equal compares key material, including prime order, but ignores cached CRT
// values. Only another *PrivateKey from this package can compare equal.
func (priv *PrivateKey) Equal(other crypto.PrivateKey) bool {
	key, ok := other.(*PrivateKey)
	if !ok || priv == nil || key == nil {
		return ok && priv == nil && key == nil
	}
	if priv.E != key.E || !equalInt(priv.N, key.N) || !equalInt(priv.D, key.D) || len(priv.Primes) != len(key.Primes) {
		return false
	}
	for i, prime := range priv.Primes {
		if !equalInt(prime, key.Primes[i]) {
			return false
		}
	}
	return true
}

func equalInt(a, b *big.Int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Cmp(b) == 0
}

// Validate checks the two-prime relations in RFC 8017 section 3, returning
// ErrInvalidKey for invalid key material. Do not mutate or require caches.
// This mathematical check is not SP 800-56B full/partial key validation.
func (priv *PrivateKey) Validate() error {
	// Reject nil parameters, missing primes
	if priv == nil ||
		priv.N == nil ||
		priv.D == nil ||
		len(priv.Primes) != 2 ||
		priv.Primes[0] == nil ||
		priv.Primes[1] == nil {
		return ErrInvalidKey
	}

	// Reject nonpositive, even, equal, or composite factors
	p := priv.Primes[0]
	q := priv.Primes[1]
	if p.Sign() <= 0 || q.Sign() <= 0 || p.Cmp(q) == 0 || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) || p.Bit(0) == 0 || q.Bit(0) == 0 {
		return ErrInvalidKey
	}

	// Check N = p*q and N > 0
	n := new(big.Int).Mul(p, q)
	if priv.N.Cmp(n) != 0 || priv.N.Sign() <= 0 {
		return ErrInvalidKey
	}

	// Check 3 <= e < n
	if priv.E < 3 || big.NewInt(int64(priv.E)).Cmp(priv.N) >= 0 {
		return ErrInvalidKey
	}

	// gcd(e, lcm(p-1,q-1)) = 1
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	lcm := new(big.Int).Div(new(big.Int).Mul(pMinus1, qMinus1), new(big.Int).GCD(nil, nil, pMinus1, qMinus1))
	if new(big.Int).GCD(nil, nil, big.NewInt(int64(priv.E)), lcm).Cmp(one) != 0 {
		return ErrInvalidKey
	}

	// Check 0 < d < n
	if priv.D.Cmp(big.NewInt(0)) <= 0 || priv.D.Cmp(priv.N) >= 0 {
		return ErrInvalidKey
	}

	// Check ed ≡ 1 (mod lcm(p-1,q-1))
	if new(big.Int).Mul(big.NewInt(int64(priv.E)), priv.D).Mod(new(big.Int).Mul(big.NewInt(int64(priv.E)), priv.D), lcm).Cmp(one) != 0 {
		return ErrInvalidKey
	}

	return nil
}

// Precompute derives independently owned CRT fields for a valid two-prime key.
// It is idempotent; call before concurrent use and never mutate N, D or Primes.
// Invalid/incomplete keys are left unchanged; use Validate for a checked error.
func (priv *PrivateKey) Precompute() {
	if priv.Validate() != nil {
		return
	}
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(priv.Primes[0], one)
	qMinus1 := new(big.Int).Sub(priv.Primes[1], one)

	dp := new(big.Int).Mod(priv.D, pMinus1)
	dq := new(big.Int).Mod(priv.D, qMinus1)
	qinv := new(big.Int).ModInverse(priv.Primes[1], priv.Primes[0])

	priv.Precomputed.Dp = dp
	priv.Precomputed.Dq = dq
	priv.Precomputed.Qinv = qinv
}

// Sign implements crypto.Signer. digest is already hashed by the caller.
// *PSSOptions selects PSS; other non-nil SignerOpts select PKCS #1 v1.5.
// Unlike the standard implementation, nil options return ErrInvalidOptions.
func (priv *PrivateKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, ErrInvalidOptions
	}
	if pss, ok := opts.(*PSSOptions); ok {
		if pss == nil {
			return nil, ErrInvalidOptions
		}
		return SignPSS(random, priv, pss.Hash, digest, pss)
	}
	return SignPKCS1v15(random, priv, opts.HashFunc(), digest)
}

// Decrypt implements crypto.Decrypter. Explicit OAEPOptions selects OAEP;
// nil selects legacy PKCS #1 v1.5, matching crypto/rsa's dispatch contract.
// Unknown or typed-nil options return ErrInvalidOptions.
func (priv *PrivateKey) Decrypt(random io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	switch opts := opts.(type) {
	case nil:
		return DecryptPKCS1v15(random, priv, ciphertext)
	case *OAEPOptions:
		if opts == nil {
			return nil, ErrInvalidOptions
		}
		return decryptOAEPWithOptions(random, priv, ciphertext, opts)
	case *PKCS1v15DecryptOptions:
		if opts == nil {
			return nil, ErrInvalidOptions
		}
		if opts.SessionKeyLen > 0 {
			return decryptSessionKey(random, priv, ciphertext, opts.SessionKeyLen)
		}
		return DecryptPKCS1v15(random, priv, ciphertext)
	default:
		return nil, ErrInvalidOptions
	}
}
