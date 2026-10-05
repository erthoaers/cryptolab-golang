// RSA signature schemes from PKCS #1 v2.2 / RFC 8017 sections 8-9:
// RSASSA-PSS and RSASSA-PKCS1-v1_5. Both are part of the same specification.
package rsa

import (
	"crypto"
	"crypto/subtle"
	"hash"
	"io"
)

func emsaPSSEncode(
	h hash.Hash,
	digest, salt []byte,
	emBits int,
) ([]byte, error) {
	if h == nil || digest == nil || emBits <= 0 {
		return nil, ErrInvalidOptions
	}

	emLen := (emBits + 7) / 8
	if len(digest) != h.Size() || emLen < h.Size()+len(salt)+2 {
		return nil, ErrInvalidOptions
	}

	mPrime := make([]byte, 8+len(digest)+len(salt))
	copy(mPrime[8:], digest)
	copy(mPrime[8+len(digest):], salt)
	h.Reset()
	h.Write(mPrime)
	hHash := h.Sum(nil)

	db := make([]byte, emLen-len(hHash)-1)
	psLen := emLen - len(hHash) - len(salt) - 2
	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	// MGF1 to generate dbMask from hHash
	dbMask, err := mgf1(h, hHash, len(db))
	if err != nil {
		return nil, err
	}
	// XOR db with dbMask
	for i := 0; i < len(db); i++ {
		db[i] ^= dbMask[i]
	}
	db[0] &= byte(0xff >> (8*emLen - emBits))
	// Concatenate db and hHash and 0xbc
	em := make([]byte, len(db)+len(hHash)+1)
	copy(em, db)
	copy(em[len(db):], hHash)
	em[len(db)+len(hHash)] = 0xbc
	return em, nil
}

// SignPSS signs an already computed digest (RFC 8017 sections 8.1.1 and 9.1.1).
// A nonzero opts.Hash overrides hashID. Nil opts means automatic salt length.
// Auto uses the largest fitting salt; EqualsHash uses the digest size; positive
// lengths are exact. Reject other negative lengths and wrong digest lengths.
// Use emBits=N.BitLen()-1, but return exactly PublicKey.Size() signature bytes.
// Resolve the hash via newHash; do not modify key, digest or opts.
func SignPSS(random io.Reader, priv *PrivateKey, hashID crypto.Hash, digest []byte, opts *PSSOptions) ([]byte, error) {
	if opts != nil && opts.Hash != 0 {
		hashID = opts.Hash
	}
	h, err := newHash(hashID)
	if err != nil {
		return nil, err
	}

	hLen := h.Size()
	emBits := priv.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	maxSaltLen := emLen - hLen - 2

	if len(digest) != hLen || maxSaltLen < 0 {
		return nil, ErrInvalidOptions
	}

	sLen := PSSSaltLengthAuto
	if opts != nil {
		sLen = opts.SaltLength
	}

	switch sLen {
	case PSSSaltLengthAuto:
		sLen = maxSaltLen
	case PSSSaltLengthEqualsHash:
		sLen = hLen
	}

	if sLen < 0 || sLen > maxSaltLen {
		return nil, ErrInvalidOptions
	}

	salt := make([]byte, sLen)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, err
	}

	em, err := emsaPSSEncode(h, digest, salt, emBits)
	if err != nil {
		return nil, err
	}
	s, err := RSASP1(priv, OS2IP(em))
	if err != nil {
		return nil, err
	}
	return I2OSP(s, priv.Size())
}

func emsaPSSVerify(
	h hash.Hash,
	digest, em []byte,
	emBits, saltLength int,
) error {
	emLen := (emBits + 7) / 8
	if emBits <= 0 ||
		len(digest) != h.Size() ||
		len(em) != emLen ||
		emLen < h.Size()+2 ||
		em[emLen-1] != 0xbc {
		return ErrVerification
	}

	dbLen := emLen - h.Size() - 1
	maskedDB := make([]byte, dbLen)
	copy(maskedDB, em[:dbLen])
	hHash := em[dbLen : emLen-1]

	keepMask := byte(0xff) >> (8*emLen - emBits)
	if maskedDB[0]&^keepMask != 0 {
		return ErrVerification
	}
	dbMask, err := mgf1(h, hHash, dbLen)
	if err != nil {
		return err
	}
	for i := 0; i < dbLen; i++ {
		maskedDB[i] ^= dbMask[i]
	}

	maskedDB[0] &= keepMask
	// Scan the data block for the delimiter (0x01) and check for invalid bytes (anything other than 0x00 or 0x01) before the delimiter.

	delimiterIndex := 0
	valid := 0

	for i := 0; i < len(maskedDB); i++ {
		if maskedDB[i] != 0 && maskedDB[i] != 1 {
			return ErrVerification
		}
		if maskedDB[i] == 1 {
			delimiterIndex = i
			valid = 1
			break
		}
	}
	if valid == 0 {
		return ErrVerification
	}

	salt := maskedDB[delimiterIndex+1:]
	if saltLength != 0 && len(salt) != saltLength {
		return ErrVerification
	}

	mPrime := make([]byte, 8+h.Size()+len(salt))
	copy(mPrime[8:8+h.Size()], digest)
	copy(mPrime[8+h.Size():], salt)
	h.Reset()
	h.Write(mPrime)
	hSum := h.Sum(nil)

	if subtle.ConstantTimeCompare(hSum, hHash) != 1 {
		return ErrVerification
	}
	return nil
}

// VerifyPSS verifies digest and sig (RFC 8017 sections 8.1.2 and 9.1.2).
// Like crypto/rsa, hashID selects the hash here; opts.Hash is ignored.
// Auto detects salt length; EqualsHash and positive lengths enforce a length.
// Invalid signatures return ErrVerification. Preserve every input.
func VerifyPSS(pub *PublicKey, hashID crypto.Hash, digest, sig []byte, opts *PSSOptions) error {
	h, err := newHash(hashID)
	if err != nil {
		return err
	}
	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8

	if len(sig) != pub.Size() {
		return ErrVerification
	}
	m, err := RSAVP1(pub, OS2IP(sig))
	if err != nil {
		return ErrVerification
	}
	em, err := I2OSP(m, emLen)
	if err != nil {
		return ErrVerification
	}

	sLen := PSSSaltLengthAuto
	if opts != nil {
		sLen = opts.SaltLength
	}
	switch sLen {
	case PSSSaltLengthAuto:
		sLen = 0
	case PSSSaltLengthEqualsHash:
		sLen = h.Size()
	}
	if sLen < 0 {
		return ErrInvalidOptions
	}

	return emsaPSSVerify(h, digest, em, emBits, sLen)
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
