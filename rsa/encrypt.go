// RSA encryption schemes from PKCS #1 v2.2 / RFC 8017 section 7:
// RSAES-OAEP and RSAES-PKCS1-v1_5. Both are part of the same specification.
package rsa

import (
	"hash"
	"io"
)

// EncryptOAEP encrypts msg using h for both OAEP and MGF1 (RFC 8017 7.1.1).
// Read the seed from random; preserve msg and label. Enforce the k-2*hLen-2
// bound with ErrMessageTooLong and return a ciphertext of exactly k bytes.
func EncryptOAEP(
	h hash.Hash,
	random io.Reader,
	pub *PublicKey,
	msg, label []byte,
) ([]byte, error) {
	return encryptOAEP(h, h, random, pub, msg, label)
}

// EncryptOAEPWithOptions accepts the standard options type. A zero MGFHash
// selects Hash; otherwise the two hashes may differ. Resolve both with newHash.
// Nil options return ErrInvalidOptions; Hash must identify a supported hash.
func EncryptOAEPWithOptions(random io.Reader, pub *PublicKey, msg []byte, opts *OAEPOptions) ([]byte, error) {
	if opts == nil {
		return nil, ErrInvalidOptions
	}
	h, err := newHash(opts.Hash)
	if err != nil {
		return nil, err
	}
	mgfHash := h
	if opts.MGFHash != 0 {
		mgfHash, err = newHash(opts.MGFHash)
		if err != nil {
			return nil, err
		}
	}
	return encryptOAEP(h, mgfHash, random, pub, msg, opts.Label)
}

func encryptOAEP(
	h, mgfHash hash.Hash,
	random io.Reader,
	pub *PublicKey,
	msg, label []byte,
) ([]byte, error) {
	if uint64(len(label)) > 1<<61-1 {
		return nil, ErrMessageTooLong
	}

	k := pub.Size()
	hLen := h.Size()
	if len(msg) > k-2*hLen-2 {
		return nil, ErrMessageTooLong
	}

	// If the label is nil, treat it as an empty byte slice. Then hash the label to produce lHash.
	if label == nil {
		label = []byte{}
	}
	h.Reset()
	h.Write(label)
	lHash := h.Sum(nil)
	// Construct the data block (DB) for OAEP encoding. The DB consists of:
	// lHash || PS || 0x01 || msg, where PS is a padding string of zeros.
	db := make([]byte, k-hLen-1)
	copy(db[:hLen], lHash)
	db[k-hLen-1-len(msg)-1] = 0x01
	copy(db[k-hLen-1-len(msg):], msg)
	// Generate a random seed of length hLen for OAEP encoding.
	seed := make([]byte, hLen)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, err
	}
	// Mask the data block (DB) and the seed using MGF1 to produce the final encoded message.
	dbMask, err := mgf1(mgfHash, seed, k-hLen-1)
	if err != nil {
		return nil, err
	}
	// XOR the data block (DB) with the mask to produce the maskedDB.
	maskedDB := make([]byte, len(db))
	for i := 0; i < len(db); i++ {
		maskedDB[i] = db[i] ^ dbMask[i]
	}
	// XOR the seed with the seed mask to produce the maskedSeed.
	maskedSeed := make([]byte, len(seed))
	seedMask, err := mgf1(mgfHash, maskedDB, hLen)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(seed); i++ {
		maskedSeed[i] = seed[i] ^ seedMask[i]
	}
	// The final encoded message is 0x00 || maskedSeed || maskedDB.
	em := make([]byte, k)
	em[0] = 0x00
	copy(em[1:1+hLen], maskedSeed)
	copy(em[1+hLen:], maskedDB)

	// Convert the encoded message (EM) to an integer message representative (m) using OS2IP.
	m := OS2IP(em)
	c, err := RSAEP(pub, m)
	if err != nil {
		return nil, err
	}
	// Convert the ciphertext integer (c) back to an octet string of length k using I2OSP.
	ciphertext, err := I2OSP(c, k)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptOAEP decrypts using h for both OAEP and MGF1 (RFC 8017 7.1.2).
// Preserve ciphertext and label. Invalid length, range, label hash, padding
// or delimiter must produce nil, ErrDecryption without exposing the cause.
func DecryptOAEP(h hash.Hash, random io.Reader, priv *PrivateKey, ciphertext, label []byte) ([]byte, error) {
	panic(todo("TODO RSA-07: implement RSAES-OAEP decryption; RFC 8017 section 7.1.2"))
}

// decryptOAEPWithOptions is the Decrypter path supporting independent MGFHash.
// It must enforce the same decoding checks as DecryptOAEP.
func decryptOAEPWithOptions(random io.Reader, priv *PrivateKey, ciphertext []byte, opts *OAEPOptions) ([]byte, error) {
	panic(todo("TODO RSA-07: implement OAEP decryption with options; RFC 8017 section 7.1.2"))
}

// EncryptPKCS1v15 is the legacy RSAES-PKCS1-v1_5 exercise (RFC 8017 7.2.1).
// Use nonzero random padding bytes and enforce len(msg)<=k-11. Prefer OAEP in
// new uses. Input buffers and key material must remain unchanged.
func EncryptPKCS1v15(random io.Reader, pub *PublicKey, msg []byte) ([]byte, error) {
	panic(todo("TODO RSA-09: implement PKCS1-v1_5 encryption; RFC 8017 section 7.2.1"))
}

// DecryptPKCS1v15 returns ErrDecryption for malformed encoding (RFC 8017 7.2.2).
// Ordinary error-returning v1.5 decryption is not a session-key protocol.
func DecryptPKCS1v15(random io.Reader, priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	panic(todo("TODO RSA-09: implement PKCS1-v1_5 decryption; RFC 8017 section 7.2.2"))
}

// DecryptPKCS1v15SessionKey preserves a pre-randomized key on invalid padding
// or a wrong plaintext length, returning nil for those cases. Invalid public
// ciphertext length/range can return ErrDecryption. On valid input copy the
// recovered key into key. Study RFC 8017 7.2.2 notes and Go's API contract;
// no padding-validity branch may be exposed to the caller.
func DecryptPKCS1v15SessionKey(random io.Reader, priv *PrivateKey, ciphertext, key []byte) error {
	panic(todo("TODO RSA-09: implement session-key decoding; RFC 8017 section 7.2.2 and Go API contract"))
}

// decryptSessionKey first fills a fresh buffer from random, then calls
// DecryptPKCS1v15SessionKey. On malformed padding it returns that fallback.
// Propagate random-source errors before attempting decryption.
func decryptSessionKey(random io.Reader, priv *PrivateKey, ciphertext []byte, length int) ([]byte, error) {
	panic(todo("TODO RSA-09: implement randomized session-key fallback; Go Decrypter contract"))
}
