// RSA signature schemes from PKCS #1 v2.2 / RFC 8017 sections 8-9:
// RSASSA-PSS and RSASSA-PKCS1-v1_5. Both are part of the same specification.
package rsa

import (
	"crypto"
	"io"
)

// SignPSS signs an already computed digest (RFC 8017 sections 8.1.1 and 9.1.1).
// A nonzero opts.Hash overrides hashID. Nil opts means automatic salt length.
// Auto uses the largest fitting salt; EqualsHash uses the digest size; positive
// lengths are exact. Reject other negative lengths and wrong digest lengths.
// Use emBits=N.BitLen()-1, but return exactly PublicKey.Size() signature bytes.
// Resolve the hash via newHash; do not modify key, digest or opts.
func SignPSS(random io.Reader, priv *PrivateKey, hashID crypto.Hash, digest []byte, opts *PSSOptions) ([]byte, error) {
	panic(todo("TODO RSA-08: implement RSASSA-PSS signing; RFC 8017 sections 8.1.1 and 9.1.1"))
}

// VerifyPSS verifies digest and sig (RFC 8017 sections 8.1.2 and 9.1.2).
// Like crypto/rsa, hashID selects the hash here; opts.Hash is ignored.
// Auto detects salt length; EqualsHash and positive lengths enforce a length.
// Invalid signatures return ErrVerification. Preserve every input.
func VerifyPSS(pub *PublicKey, hashID crypto.Hash, digest, sig []byte, opts *PSSOptions) error {
	panic(todo("TODO RSA-08: implement RSASSA-PSS verification; RFC 8017 sections 8.1.2 and 9.1.2"))
}

// SignPKCS1v15 signs a digest with EMSA-PKCS1-v1_5 (RFC 8017 8.2.1 and 9.2).
// hashID=0 signs the supplied bytes without a DigestInfo prefix, matching the
// standard API's legacy behavior. Otherwise check the digest length and DER
// prefix. This scheme is deterministic; random is retained for API parity.
func SignPKCS1v15(random io.Reader, priv *PrivateKey, hashID crypto.Hash, digest []byte) ([]byte, error) {
	panic(todo("TODO RSA-09: implement PKCS1-v1_5 signing; RFC 8017 sections 8.2.1 and 9.2"))
}

// VerifyPKCS1v15 checks the complete encoding, not only its digest suffix.
// hashID=0 has the same raw-byte meaning as SignPKCS1v15. Preserve inputs.
func VerifyPKCS1v15(pub *PublicKey, hashID crypto.Hash, digest, sig []byte) error {
	panic(todo("TODO RSA-09: implement PKCS1-v1_5 verification; RFC 8017 sections 8.2.2 and 9.2"))
}
