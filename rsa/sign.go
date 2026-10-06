// RSA signature schemes from PKCS #1 v2.2 / RFC 8017 sections 8-9:
// RSASSA-PSS and RSASSA-PKCS1-v1_5. Both are part of the same specification.
package rsa

import (
	"crypto"
	"crypto/subtle"
	"hash"
	"io"
)

var digestInfoPrefixes = map[crypto.Hash][]byte{
	crypto.SHA1:       {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:     {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:     {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.SHA512_224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA512_256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20},
}

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

func emsaPKCS1v15Encode(
	hash crypto.Hash,
	digest []byte,
	emLen int,
) ([]byte, error) {
	var digestInfoPrefix []byte
	if hash != 0 {
		if prefix, ok := digestInfoPrefixes[hash]; ok {
			digestInfoPrefix = prefix
		} else {
			return nil, ErrUnsupportedHash
		}
		h, err := newHash(hash)
		if err != nil {
			return nil, err
		}
		if len(digest) != h.Size() {
			return nil, ErrInvalidOptions
		}
	}
	tLen := len(digestInfoPrefix) + len(digest)
	if emLen < 11 || emLen < tLen+11 {
		return nil, ErrMessageTooLong
	}
	em := make([]byte, emLen)
	copy(em[len(em)-len(digest):], digest)
	copy(em[len(em)-tLen:len(em)-len(digest)], digestInfoPrefix)
	em[0] = 0
	em[1] = 1
	for i := 2; i < emLen-tLen-1; i++ {
		em[i] = 0xff
	}
	em[emLen-tLen-1] = 0
	return em, nil
}

// SignPKCS1v15 signs a digest with EMSA-PKCS1-v1_5 (RFC 8017 8.2.1 and 9.2).
// hashID=0 signs the supplied bytes without a DigestInfo prefix, matching the
// standard API's legacy behavior. Otherwise check the digest length and DER
// prefix. This scheme is deterministic; random is retained for API parity.
func SignPKCS1v15(random io.Reader, priv *PrivateKey, hashID crypto.Hash, digest []byte) ([]byte, error) {
	emLen := priv.Size()
	em, err := emsaPKCS1v15Encode(hashID, digest, emLen)
	if err != nil {
		return nil, err
	}
	m := OS2IP(em)
	s, err := RSASP1(priv, m)
	if err != nil {
		return nil, err
	}
	return I2OSP(s, emLen)
}

// VerifyPKCS1v15 checks the complete encoding, not only its digest suffix.
// hashID=0 has the same raw-byte meaning as SignPKCS1v15. Preserve inputs.
func VerifyPKCS1v15(pub *PublicKey, hashID crypto.Hash, digest, sig []byte) error {
	if len(sig) != pub.Size() {
		return ErrVerification
	}
	m, err := RSAVP1(pub, OS2IP(sig))
	if err != nil {
		return ErrVerification
	}
	em, err := I2OSP(m, pub.Size())
	if err != nil {
		return ErrVerification
	}
	emExpected, err := emsaPKCS1v15Encode(hashID, digest, pub.Size())
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(em, emExpected) != 1 {
		return ErrVerification
	}
	return nil
}
