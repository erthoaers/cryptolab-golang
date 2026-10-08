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
	panic(todo("TODO RSA-11a: sample an invertible blinding factor and its inverse"))
}
