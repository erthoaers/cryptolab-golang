// Shared building blocks for RFC 8017: data conversion (section 4), RSA
// integer primitives (section 5), and hash/MGF1 helpers (Appendix B).
package rsa

import (
	"crypto"
	"github.com/erthoaers/cryptolab-golang/sha1"
	"github.com/erthoaers/cryptolab-golang/sha256"
	"github.com/erthoaers/cryptolab-golang/sha512"
	"hash"
	"math/big"
)

// I2OSP encodes x as exactly xLen big-endian bytes, including leading zeros.
// It returns ErrInvalidInteger for nil/negative x, ErrInvalidLength for negative
// xLen, or ErrIntegerTooLarge if x does not fit. Zero fits in zero bytes.
// The result is newly allocated and x must remain unchanged.
func I2OSP(x *big.Int, xLen int) ([]byte, error) {
	if x == nil || x.Sign() < 0 {
		return nil, ErrInvalidInteger
	}
	if xLen < 0 {
		return nil, ErrInvalidLength
	}

	xBytes := x.Bytes()
	if len(xBytes) > xLen {
		return nil, ErrIntegerTooLarge
	}

	result := make([]byte, xLen)
	copy(result[xLen-len(xBytes):], xBytes)
	return result, nil
}

// OS2IP interprets x as an unsigned big-endian integer. Empty input means zero.
// It returns a new integer without changing or retaining the input bytes.
func OS2IP(x []byte) *big.Int {
	if len(x) == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(x)
}

// The following primitives assume valid, unmodified keys, as in RFC 8017
// section 5. They do not validate imported key material. For every primitive:
// return nil, ErrRepresentativeOutOfRange for a nil, negative, or >= N input;
// otherwise return a new integer without mutating/aliasing the key or input.

// RSAEP applies the public exponent to a message representative (section 5.1.1).
func RSAEP(key *PublicKey, m *big.Int) (*big.Int, error) {
	if m == nil || m.Sign() < 0 || m.Cmp(key.N) >= 0 {
		return nil, ErrRepresentativeOutOfRange
	}
	return new(big.Int).Exp(m, big.NewInt(int64(key.E)), key.N), nil
}

// RSADP uses the direct (N,D) representation (section 5.1.2, step 2.a).
// It needs only N and D; the factor and CRT fields may be nil.
func RSADP(key *PrivateKey, c *big.Int) (*big.Int, error) {
	if c == nil || c.Sign() < 0 || c.Cmp(key.N) >= 0 {
		return nil, ErrRepresentativeOutOfRange
	}
	return new(big.Int).Exp(c, key.D, key.N), nil
}

// RSADPCRT uses (Primes[0],Primes[1],Precomputed.Dp,Dq,Qinv) (section 5.1.2, step 2.b).
// N is also present for range checking; D may be nil.
// Keep this path separate from RSADP so both representations can be compared.
func RSADPCRT(key *PrivateKey, c *big.Int) (*big.Int, error) {
	if c == nil || c.Sign() < 0 || c.Cmp(key.N) >= 0 {
		return nil, ErrRepresentativeOutOfRange
	}

	if key.Precomputed.Dp == nil || key.Precomputed.Dq == nil || key.Precomputed.Qinv == nil {
		return nil, ErrInvalidKey
	}
	p := key.Primes[0]
	q := key.Primes[1]
	dP := key.Precomputed.Dp
	dQ := key.Precomputed.Dq
	qInv := key.Precomputed.Qinv

	// m1 = c^dP mod p
	m1 := new(big.Int).Exp(c, dP, p)
	// m2 = c^dQ mod q
	m2 := new(big.Int).Exp(c, dQ, q)
	// h = qInv * (m1 - m2) mod p
	h := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(m1, m2), qInv), p)
	// m = m2 + h * q
	m := new(big.Int).Add(m2, new(big.Int).Mul(h, q))
	return m, nil
}

// RSASP1 applies the private exponent to an already encoded representative.
// This is not a complete message-signing API (section 5.2.1).
func RSASP1(key *PrivateKey, m *big.Int) (*big.Int, error) {
	if key.Precomputed.Dp != nil &&
		key.Precomputed.Dq != nil &&
		key.Precomputed.Qinv != nil &&
		key.Primes != nil && len(key.Primes) == 2 &&
		key.Primes[0] != nil &&
		key.Primes[1] != nil {
		return RSADPCRT(key, m)
	}
	return RSADP(key, m)
}

// RSAVP1 recovers an encoded representative; it does not verify a message.
// A complete signature scheme must also check the encoding (section 5.2.2).
func RSAVP1(key *PublicKey, s *big.Int) (*big.Int, error) {
	return RSAEP(key, s)
}

// newHash maps SHA identifiers to this workspace's SHA-1/SHA-2 constructors.
// Do not change crypto's global hash registry or use a standard hash as the
// implementation. Unsupported identifiers return nil, ErrUnsupportedHash.
func newHash(id crypto.Hash) (hash.Hash, error) {
	switch id {
	case crypto.SHA1:
		return sha1.New(), nil
	case crypto.SHA224:
		return sha256.New224(), nil
	case crypto.SHA256:
		return sha256.New(), nil
	case crypto.SHA384:
		return sha512.New384(), nil
	case crypto.SHA512:
		return sha512.New(), nil
	case crypto.SHA512_224:
		return sha512.New512_224(), nil
	case crypto.SHA512_256:
		return sha512.New512_256(), nil
	default:
		return nil, ErrUnsupportedHash
	}
}

// mgf1 returns length bytes according to RFC 8017 Appendix B.2.1. Reset h
// between counter blocks; do not change seed. Negative length returns
// ErrInvalidLength; an excessive mask length returns ErrMessageTooLong.
func mgf1(h hash.Hash, seed []byte, length int) ([]byte, error) {
	if length < 0 {
		return nil, ErrInvalidLength
	}
	hLen := h.Size()
	if int64(length) > (1<<32)*int64(hLen) {
		return nil, ErrMessageTooLong
	}
	blocks := (length + hLen - 1) / hLen
	T := make([]byte, 0, blocks*hLen)
	for i := 0; i < blocks; i++ {
		counter, err := I2OSP(big.NewInt(int64(i)), 4)
		if err != nil {
			return nil, err
		}
		h.Reset()
		h.Write(seed)
		h.Write(counter)
		T = append(T, h.Sum(nil)...)
	}
	return T[:length], nil
}
