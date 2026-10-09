// Internal helpers for the RSA private-operation blinding exercise.
package rsa

import (
	"io"
	"math/big"
)

// randomBlindingFactor samples r and its multiplicative inverse modulo n.
// Require an odd n > 1; reject invalid n with ErrInvalidKey before reading.
// A nil random source returns ErrInvalidOptions. Errors return nil, nil, err.
//
// Read ceil(n.BitLen()/8) bytes per candidate with io.ReadFull and clear only
// the excess high bits. Reject zero, candidates >= n, and candidates without
// an inverse. Refill the buffer for each retry; propagate reader errors.
// With a uniform random source, rejection sampling is uniform over the units
// modulo n. The value 1 is allowed. Do not force candidates to be odd or prime,
// or reduce out-of-range candidates modulo n.
//
// Return independent integers; preserve n. This helper is not yet connected
// to the encryption or signature schemes. See docs/rsa.md, step RSA-11a.
func randomBlindingFactor(random io.Reader, n *big.Int) (r, rInv *big.Int, err error) {
	if n == nil || n.Cmp(big.NewInt(1)) <= 0 || n.Bit(0) == 0 {
		return nil, nil, ErrInvalidKey
	}
	if random == nil {
		return nil, nil, ErrInvalidOptions
	}

	bitLen := n.BitLen()
	byteLen := (bitLen + 7) / 8
	excess := byteLen*8 - bitLen
	buf := make([]byte, byteLen)

	for {
		if _, err := io.ReadFull(random, buf); err != nil {
			return nil, nil, err
		}
		buf[0] &= byte(0xFF >> excess)

		r = new(big.Int).SetBytes(buf)
		if r.Sign() <= 0 || r.Cmp(n) >= 0 {
			continue
		}
		rInv = new(big.Int).ModInverse(r, n)
		if rInv != nil {
			return r, rInv, nil
		}
	}
}
