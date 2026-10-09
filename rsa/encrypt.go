// RSA encryption schemes from PKCS #1 v2.2 / RFC 8017 section 7:
// RSAES-OAEP and RSAES-PKCS1-v1_5. Both are part of the same specification.
package rsa

import (
	"crypto/subtle"
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
func EncryptOAEPWithOptions(
	random io.Reader,
	pub *PublicKey,
	msg []byte,
	opts *OAEPOptions,
) ([]byte, error) {
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
	// Check that the label length does not exceed the maximum allowed value.
	if uint64(len(label)) > 1<<61-1 {
		return nil, ErrMessageTooLong
	}
	// Determine the length of the RSA modulus in bytes (k) and the hash output length (hLen).
	// Check that the message length does not exceed the maximum allowed for OAEP encoding.
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
// Use random for blinding and propagate random-source errors.
func DecryptOAEP(
	h hash.Hash,
	random io.Reader,
	priv *PrivateKey,
	ciphertext, label []byte,
) ([]byte, error) {
	return decryptOAEP(h, h, random, priv, ciphertext, label)
}

// decryptOAEPWithOptions is the Decrypter path supporting independent MGFHash.
// It must enforce the same decoding checks as DecryptOAEP.
func decryptOAEPWithOptions(random io.Reader, priv *PrivateKey, ciphertext []byte, opts *OAEPOptions) ([]byte, error) {
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
	return decryptOAEP(h, mgfHash, random, priv, ciphertext, opts.Label)
}

func decryptOAEP(
	h, mgfHash hash.Hash,
	random io.Reader,
	priv *PrivateKey,
	ciphertext, label []byte,
) ([]byte, error) {
	// Check that the label length does not exceed the maximum allowed value.
	if uint64(len(label)) > 1<<61-1 {
		return nil, ErrDecryption
	}
	// Determine the length of the RSA modulus in bytes (k) and the hash output length (hLen).
	// Check that the ciphertext length matches the expected length for the RSA modulus.
	k := priv.Size()
	if len(ciphertext) != k {
		return nil, ErrDecryption
	}
	hLen := h.Size()
	if k < 2*hLen+2 {
		return nil, ErrDecryption
	}

	// Convert the ciphertext to an integer representative and check its range.
	c := OS2IP(ciphertext)
	if c.Cmp(priv.N) >= 0 {
		return nil, ErrDecryption
	}

	m, err := privateOpBlinded(random, priv, c)
	if err != nil {
		return nil, err
	}
	// Convert the message representative (m) to an encoded message (EM) of length k using I2OSP.
	em, err := I2OSP(m, k)
	if err != nil {
		return nil, ErrDecryption
	}
	// Separate the encoded message into its components: Y, maskedSeed, and maskedDB.
	y := em[0]
	maskedSeed := em[1 : 1+hLen]
	maskedDB := em[1+hLen:]

	// Compute the seed by XORing the maskedSeed with the seedMask derived from the maskedDB.
	seedMask, err := mgf1(mgfHash, maskedDB, hLen)
	if err != nil {
		return nil, ErrDecryption
	}
	seed := make([]byte, hLen)
	for i := 0; i < hLen; i++ {
		seed[i] = maskedSeed[i] ^ seedMask[i]
	}
	// Compute the data block (DB) by XORing the maskedDB with the dbMask derived from the seed.
	dbMask, err := mgf1(mgfHash, seed, k-1-hLen)
	if err != nil {
		return nil, ErrDecryption
	}
	db := make([]byte, k-1-hLen)
	for i := 0; i < len(db); i++ {
		db[i] = maskedDB[i] ^ dbMask[i]
	}
	// Check that the first byte of the data block is 0x00 as required by the OAEP encoding.
	if len(db) == 0 {
		return nil, ErrDecryption
	}

	// Verify that the hash of the label matches the corresponding portion of the data block.
	h.Reset()
	h.Write(label)
	lHash := h.Sum(nil)
	valid := subtle.ConstantTimeByteEq(y, 0) &
		subtle.ConstantTimeCompare(db[:hLen], lHash)

	// Scan the data block for the delimiter (0x01) and check for invalid bytes (anything other than 0x00 or 0x01) before the delimiter.
	looking := 1
	bad := 0
	delimiterIndex := 0

	for i := hLen; i < len(db); i++ {
		isZero := subtle.ConstantTimeByteEq(db[i], 0)
		isOne := subtle.ConstantTimeByteEq(db[i], 1)

		// Check for invalid bytes before the delimiter. Only 0x00 and 0x01 are allowed.
		bad |= looking & (1 ^ (isZero | isOne))

		// Record the index of the first 0x01 byte as the delimiter.
		delimiterIndex = subtle.ConstantTimeSelect(
			looking&isOne, i, delimiterIndex,
		)
		looking &= 1 ^ isOne
	}

	valid &= (1 ^ bad) & (1 ^ looking)
	if valid != 1 {
		return nil, ErrDecryption
	}
	return db[delimiterIndex+1:], nil
}

// EncryptPKCS1v15 is the legacy RSAES-PKCS1-v1_5 exercise (RFC 8017 7.2.1).
// Use nonzero random padding bytes and enforce len(msg)<=k-11. Prefer OAEP in
// new uses. Input buffers and key material must remain unchanged.
func EncryptPKCS1v15(random io.Reader, pub *PublicKey, msg []byte) ([]byte, error) {
	k := pub.Size()
	if len(msg) > k-11 {
		return nil, ErrMessageTooLong
	}

	// Allocate the output buffer.
	enc := make([]byte, k)
	// Set the first two bytes as per PKCS1 v1.5.
	enc[0] = 0
	enc[1] = 2

	// Fill the padding bytes with nonzero random values.
	paddingLen := k - len(msg) - 3
	padding := enc[2 : 2+paddingLen]
	for i := 0; i < paddingLen; i++ {
		var b [1]byte
		for b[0] == 0 {
			if _, err := io.ReadFull(random, b[:]); err != nil {
				return nil, err
			}
		}
		padding[i] = b[0]
	}

	// Copy the message after the padding and delimiter.
	enc[2+paddingLen] = 0
	copy(enc[3+paddingLen:], msg)

	// Perform the RSA encryption primitive.
	c, err := RSAEP(pub, OS2IP(enc))
	if err != nil {
		return nil, err
	}
	return I2OSP(c, k)
}

// DecryptPKCS1v15 returns ErrDecryption for malformed encoding (RFC 8017 7.2.2).
// Ordinary error-returning v1.5 decryption is not a session-key protocol.
// Use random for blinding and propagate random-source errors.
func DecryptPKCS1v15(random io.Reader, priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	valid, em, index, err := decryptPKCS1v15(random, priv, ciphertext)
	if err != nil {
		return nil, err
	}
	if valid == 0 {
		return nil, ErrDecryption
	}
	return em[index:], nil
}

func decryptPKCS1v15(
	random io.Reader,
	priv *PrivateKey,
	ciphertext []byte,
) (valid int, em []byte, index int, err error) {
	k := priv.Size()
	if len(ciphertext) != k || k < 11 {
		return 0, nil, 0, ErrDecryption
	}
	if random == nil {
		return 0, nil, 0, ErrInvalidOptions
	}
	c := OS2IP(ciphertext)
	if c.Cmp(priv.N) >= 0 {
		return 0, nil, 0, ErrDecryption
	}
	m, err := privateOpBlinded(random, priv, c)
	if err != nil {
		return 0, nil, 0, err
	}

	em, err = I2OSP(m, k)
	if err != nil {
		return 0, nil, 0, ErrDecryption
	}
	valid = subtle.ConstantTimeByteEq(em[0], 0) &
		subtle.ConstantTimeByteEq(em[1], 2)

	looking := 1
	delimiterIndex := 0

	for i := 2; i < len(em); i++ {
		isZero := subtle.ConstantTimeByteEq(em[i], 0)

		delimiterIndex = subtle.ConstantTimeSelect(
			looking&isZero, i, delimiterIndex,
		)
		looking &= 1 ^ isZero
	}

	valid &= (1 ^ looking) &
		subtle.ConstantTimeLessOrEq(10, delimiterIndex)

	index = subtle.ConstantTimeSelect(valid, delimiterIndex+1, 0)
	return valid, em, index, nil
}

// DecryptPKCS1v15SessionKey preserves a pre-randomized key on invalid padding
// or a wrong plaintext length, returning nil for those cases. Invalid public
// ciphertext length/range can return ErrDecryption. On valid input copy the
// recovered key into key. Study RFC 8017 7.2.2 notes and Go's API contract;
// no padding-validity branch may be exposed to the caller.
// Use random for blinding; reader errors leave key unchanged and are returned.
func DecryptPKCS1v15SessionKey(random io.Reader, priv *PrivateKey, ciphertext, key []byte) error {
	k := priv.Size()
	if k < 11 || len(key) > k-11 {
		return ErrDecryption
	}
	if random == nil {
		return ErrInvalidOptions
	}
	valid, em, index, err := decryptPKCS1v15(random, priv, ciphertext)
	if err != nil {
		return err
	}
	valid &= subtle.ConstantTimeEq(
		int32(len(em)-index),
		int32(len(key)),
	)
	subtle.ConstantTimeCopy(valid, key, em[len(em)-len(key):])
	return nil
}

// decryptSessionKey first fills a fresh buffer from random, then calls
// DecryptPKCS1v15SessionKey. On malformed padding it returns that fallback.
// Propagate random-source errors from fallback generation or blinding.
func decryptSessionKey(random io.Reader, priv *PrivateKey, ciphertext []byte, length int) ([]byte, error) {
	if random == nil {
		return nil, ErrInvalidOptions
	}
	key := make([]byte, length)
	_, err := io.ReadFull(random, key)
	if err != nil {
		return nil, err
	}
	err = DecryptPKCS1v15SessionKey(random, priv, ciphertext, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
