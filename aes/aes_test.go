package aes

import (
	"bytes"
	standard "crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
)

// NIST AES_Core128.pdf, ECB-AES128 encryption/decryption examples, pages 1-7.
// Each row is an independent single-block test; this package does not implement ECB.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
const exampleKey = "2b7e151628aed2a6abf7158809cf4f3c"

var knownAnswers = []struct {
	plaintext, ciphertext string
}{
	{"6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"},
	{"ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"},
	{"30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"},
	{"f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"},
}

func blockHex(t *testing.T, encoded string) [16]byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 16 {
		t.Fatalf("bad test fixture %q: decoded length=%d, error=%v", encoded, len(decoded), err)
	}
	return [16]byte(decoded)
}

// Algorithm: FIPS 197-upd1 (2023), sections 5.1 and 5.3.
// Each fixture is the first independent block in NIST's encryption/decryption
// examples; these tests do not implement ECB or apply padding.
// AES_Core128.pdf: key/plaintext p. 1, ciphertext p. 6.
// AES_Core192.pdf: key/plaintext p. 1, ciphertext pp. 7-8.
// AES_Core256.pdf: key/plaintext p. 1, ciphertext pp. 8-9.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core192.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf
var blockFixtures = []struct {
	name, key, plaintext, ciphertext string
}{
	{"AES128", "2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"},
	{"AES192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc"},
	{"AES256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"},
}

func keyHex(t *testing.T, encoded string) []byte {
	t.Helper()
	key, err := hex.DecodeString(encoded)
	if err != nil || (len(key) != 16 && len(key) != 24 && len(key) != 32) {
		t.Fatalf("bad key fixture %q: decoded length=%d, error=%v", encoded, len(key), err)
	}
	return key
}

func newExerciseBlock(t *testing.T, key []byte) cipher.Block {
	t.Helper()
	block, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher with %d-byte key: %v", len(key), err)
	}
	if block == nil {
		t.Fatal("NewCipher returned a nil block without an error")
	}
	return block
}

func blockOperation(block cipher.Block, decrypt bool) func([]byte, []byte) {
	if decrypt {
		return block.Decrypt
	}
	return block.Encrypt
}

func requireBlockPanic(t *testing.T, call func()) {
	t.Helper()
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("invalid buffers did not cause a panic")
		}
	}()
	call()
}

func TestXtime(t *testing.T) {
	// FIPS 197-upd1 section 4.2, Eq. (4.6), plus zero and high-bit boundaries.
	cases := []struct{ input, want byte }{
		{0x00, 0x00}, {0x01, 0x02}, {0x7f, 0xfe}, {0x80, 0x1b}, {0xff, 0xe5},
		{0x57, 0xae}, {0xae, 0x47}, {0x47, 0x8e}, {0x8e, 0x07},
		{0x07, 0x0e}, {0x0e, 0x1c}, {0x1c, 0x38},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%02x", tc.input), func(t *testing.T) {
			if got := xtime(tc.input); got != tc.want {
				t.Fatalf("xtime(%02x) = %02x, want %02x", tc.input, got, tc.want)
			}
		})
	}
}

// Intermediate states from the first block, first round of AES_Core128.pdf.
func TestSubBytes(t *testing.T) {
	state := blockHex(t, "40bfabf406ee4d3042ca6b997a5c5816")
	want := blockHex(t, "090862bf6f28e3042c747feeda4a6a47")
	subBytes(&state)
	if state != want {
		t.Fatalf("SubBytes = %x, want %x", state, want)
	}
}

func TestShiftRows(t *testing.T) {
	state := blockHex(t, "090862bf6f28e3042c747feeda4a6a47")
	want := blockHex(t, "09287f476f746abf2c4a6204da08e3ee")
	shiftRows(&state)
	if state != want {
		t.Fatalf("ShiftRows = %x, want %x; check state[r+4*c] indexing", state, want)
	}
}

func TestMixColumns(t *testing.T) {
	state := blockHex(t, "09287f476f746abf2c4a6204da08e3ee")
	want := blockHex(t, "529f16c2978615cae01aae54ba1a2659")
	mixColumns(&state)
	if state != want {
		t.Fatalf("MixColumns = %x, want %x", state, want)
	}
}

func TestAddRoundKey(t *testing.T) {
	state := blockHex(t, knownAnswers[0].plaintext)
	want := blockHex(t, "40bfabf406ee4d3042ca6b997a5c5816")
	addRoundKey(&state, blockHex(t, exampleKey))
	if state != want {
		t.Fatalf("AddRoundKey = %x, want %x", state, want)
	}
}

func TestExpandKey(t *testing.T) {
	// FIPS 197-upd1 Appendix A.1, all 44 words, grouped into round keys.
	wantRounds := []string{
		exampleKey,
		"a0fafe1788542cb123a339392a6c7605",
		"f2c295f27a96b9435935807a7359f67f",
		"3d80477d4716fe3e1e237e446d7a883b",
		"ef44a541a8525b7fb671253bdb0bad00",
		"d4d1c6f87c839d87caf2b8bc11f915bc",
		"6d88a37a110b3efddbf98641ca0093fd",
		"4e54f70e5f5fc9f384a64fb24ea6dc4f",
		"ead27321b58dbad2312bf5607f8d292f",
		"ac7766f319fadc2128d12941575c006e",
		"d014f9a8c9ee2589e13f0cc8b6630ca6",
	}
	for round, encoded := range wantRounds {
		t.Run(fmt.Sprintf("round_%02d", round), func(t *testing.T) {
			key := blockHex(t, exampleKey)
			schedule, _, err := expandKey(key[:])
			if err != nil {
				t.Fatal(err)
			}
			got := [16]byte(schedule[16*round : 16*(round+1)])
			if want := blockHex(t, encoded); got != want {
				t.Fatalf("round %d key = %x, want %x", round, got, want)
			}
		})
	}
}

func TestInverseTransforms(t *testing.T) {
	// Fixed expected states are independent of the learner's forward functions.
	// FIPS 197-upd1: InvShiftRows is section 5.3.1; InvSubBytes is 5.3.2 (Table 6);
	// InvMixColumns is 5.3.3.
	cases := []struct {
		name, input, want string
		transform         func(*[16]byte)
	}{
		{"InvSubBytes", "090862bf6f28e3042c747feeda4a6a47", "40bfabf406ee4d3042ca6b997a5c5816", invSubBytes},
		{"InvShiftRows", "09287f476f746abf2c4a6204da08e3ee", "090862bf6f28e3042c747feeda4a6a47", invShiftRows},
		{"InvMixColumns", "529f16c2978615cae01aae54ba1a2659", "09287f476f746abf2c4a6204da08e3ee", invMixColumns},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := blockHex(t, tc.input)
			tc.transform(&state)
			if want := blockHex(t, tc.want); state != want {
				t.Fatalf("%s = %x, want %x", tc.name, state, want)
			}
		})
	}
}

func TestEncryptKnownAnswers(t *testing.T) {
	for i, tc := range knownAnswers {
		t.Run(fmt.Sprintf("NIST_block_%d", i+1), func(t *testing.T) {
			block := newExerciseBlock(t, keyHex(t, exampleKey))
			plaintext := blockHex(t, tc.plaintext)
			var got [16]byte
			block.Encrypt(got[:], plaintext[:])
			if want := blockHex(t, tc.ciphertext); got != want {
				t.Fatalf("ciphertext = %x, want %x", got, want)
			}
		})
	}
}

func TestDecryptKnownAnswers(t *testing.T) {
	for i, tc := range knownAnswers {
		t.Run(fmt.Sprintf("NIST_block_%d", i+1), func(t *testing.T) {
			block := newExerciseBlock(t, keyHex(t, exampleKey))
			ciphertext := blockHex(t, tc.ciphertext)
			var got [16]byte
			block.Decrypt(got[:], ciphertext[:])
			if want := blockHex(t, tc.plaintext); got != want {
				t.Fatalf("plaintext = %x, want %x", got, want)
			}
		})
	}
}

func TestVectorFixtures(t *testing.T) {
	// This test checks the fixture transcription only; it never calls a TODO.
	key := blockHex(t, exampleKey)
	oracle, err := standard.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range knownAnswers {
		t.Run(fmt.Sprintf("NIST_block_%d", i+1), func(t *testing.T) {
			plain, encrypted := blockHex(t, tc.plaintext), blockHex(t, tc.ciphertext)
			var got [16]byte
			oracle.Encrypt(got[:], plain[:])
			if got != encrypted {
				t.Fatalf("encryption fixture disagrees with crypto/aes: got %x, want %x", got, encrypted)
			}
			oracle.Decrypt(got[:], encrypted[:])
			if got != plain {
				t.Fatalf("decryption fixture disagrees with crypto/aes: got %x, want %x", got, plain)
			}
		})
	}
}

func TestDifferential(t *testing.T) {
	// Deterministic test inputs, never a source of real cryptographic keys.
	// Include zero, all-ones, and 64 varied key/block pairs.
	cases := make([]struct{ key, block [16]byte }, 66)
	for i := range cases[1].key {
		cases[1].key[i], cases[1].block[i] = 0xff, 0xff
	}
	rng := rand.New(rand.NewSource(197))
	for i := 2; i < len(cases); i++ {
		_, _ = rng.Read(cases[i].key[:])
		_, _ = rng.Read(cases[i].block[:])
	}
	for _, decrypt := range []bool{false, true} {
		t.Run(fmt.Sprintf("decrypt_%t", decrypt), func(t *testing.T) {
			for i, tc := range cases {
				oracle, err := standard.NewCipher(tc.key[:])
				if err != nil {
					t.Fatal(err)
				}
				block := newExerciseBlock(t, tc.key[:])
				var want, got [16]byte
				if decrypt {
					oracle.Decrypt(want[:], tc.block[:])
					block.Decrypt(got[:], tc.block[:])
				} else {
					oracle.Encrypt(want[:], tc.block[:])
					block.Encrypt(got[:], tc.block[:])
				}
				if got != want {
					t.Fatalf("case %d, key=%x, block=%x: got %x, want %x", i, tc.key, tc.block, got, want)
				}
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	key, plaintext := blockHex(t, exampleKey), blockHex(t, knownAnswers[0].plaintext)
	block := newExerciseBlock(t, key[:])
	var encrypted, got [16]byte
	block.Encrypt(encrypted[:], plaintext[:])
	block.Decrypt(got[:], encrypted[:])
	if got != plaintext {
		t.Fatalf("round trip = %x, want %x", got, plaintext)
	}
}

func TestBlockVectorFixtures(t *testing.T) {
	// Verify fixture transcription using an independent implementation only.
	// This test never calls the exercise's NewCipher, Encrypt, or Decrypt.
	for _, tc := range blockFixtures {
		t.Run(tc.name, func(t *testing.T) {
			oracle, err := standard.NewCipher(keyHex(t, tc.key))
			if err != nil {
				t.Fatal(err)
			}
			plain, encrypted := blockHex(t, tc.plaintext), blockHex(t, tc.ciphertext)
			var got [16]byte
			oracle.Encrypt(got[:], plain[:])
			if got != encrypted {
				t.Fatalf("encryption fixture disagrees with crypto/aes: got %x, want %x", got, encrypted)
			}
			oracle.Decrypt(got[:], encrypted[:])
			if got != plain {
				t.Fatalf("decryption fixture disagrees with crypto/aes: got %x, want %x", got, plain)
			}
		})
	}
}

func TestBlockKnownAnswers(t *testing.T) {
	for _, tc := range blockFixtures {
		for _, decrypt := range []bool{false, true} {
			operation := "Encrypt"
			if decrypt {
				operation = "Decrypt"
			}
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				block := newExerciseBlock(t, keyHex(t, tc.key))
				if got := block.BlockSize(); got != 16 {
					t.Fatalf("BlockSize = %d, want 16", got)
				}
				input, want := blockHex(t, tc.plaintext), blockHex(t, tc.ciphertext)
				if decrypt {
					input, want = want, input
				}
				var got [16]byte
				blockOperation(block, decrypt)(got[:], input[:])
				if got != want {
					t.Fatalf("got %x, want %x", got, want)
				}
			})
		}
	}
}

func TestBlockConstructor(t *testing.T) {
	// FIPS 197-upd1 Table 3; crypto/aes.NewCipher accepts only 16, 24, or 32.
	// An invalid key is a constructor error, not a panic or a usable cipher.
	for _, tc := range blockFixtures {
		t.Run(tc.name, func(t *testing.T) {
			block := newExerciseBlock(t, keyHex(t, tc.key))
			if got := block.BlockSize(); got != 16 {
				t.Fatalf("BlockSize = %d, want 16", got)
			}
		})
	}
	keys := [][]byte{nil, {}}
	for _, size := range []int{1, 15, 17, 23, 25, 31, 33} {
		keys = append(keys, make([]byte, size))
	}
	for i, key := range keys {
		t.Run(fmt.Sprintf("case_%d_len_%d", i, len(key)), func(t *testing.T) {
			block, err := NewCipher(key)
			if err == nil || block != nil {
				t.Fatalf("NewCipher with %d-byte key returned block=%v, error=%v; want nil block and error", len(key), block, err)
			}
		})
	}
}

func TestBlockSize(t *testing.T) {
	// FIPS 197-upd1 Table 3: Nb=4 for every AES key size.
	// This metadata method needs neither a key nor an initialized schedule.
	if blockSize != 16 {
		t.Fatalf("BlockSize constant = %d, want 16", blockSize)
	}
	if got := new(aesCipher).BlockSize(); got != 16 {
		t.Fatalf("BlockSize method = %d, want 16", got)
	}
}

func TestBlockDifferential(t *testing.T) {
	// FIPS 197-upd1 sections 5.1/5.3; crypto/aes is an independent oracle.
	// Deterministic zero, all-ones, and varied inputs are test data, not real keys.
	for _, keySize := range []int{16, 24, 32} {
		for caseID := 0; caseID < 10; caseID++ {
			for _, decrypt := range []bool{false, true} {
				t.Run(fmt.Sprintf("key_%d/case_%d/decrypt_%t", keySize, caseID, decrypt), func(t *testing.T) {
					key := make([]byte, keySize)
					var input [16]byte
					if caseID == 1 {
						for i := range key {
							key[i] = 0xff
						}
						for i := range input {
							input[i] = 0xff
						}
					} else if caseID > 1 {
						rng := rand.New(rand.NewSource(int64(197000 + keySize*100 + caseID)))
						_, _ = rng.Read(key)
						_, _ = rng.Read(input[:])
					}
					oracle, err := standard.NewCipher(key)
					if err != nil {
						t.Fatal(err)
					}
					block := newExerciseBlock(t, key)
					var got, want [16]byte
					blockOperation(oracle, decrypt)(want[:], input[:])
					blockOperation(block, decrypt)(got[:], input[:])
					if got != want {
						t.Fatalf("key=%x, input=%x: got %x, want %x", key, input, got, want)
					}
				})
			}
		}
	}
}

// Buffer tests follow Go 1.27.1 crypto/cipher.Block and crypto/aes behavior:
// only the first 16 bytes are read/written; exact overlap is supported;
// short buffers and inexact overlap of the active blocks cause a panic.
// https://pkg.go.dev/crypto/cipher@go1.27.1#Block
// https://go.dev/src/crypto/internal/fips140/aes/aes.go
func TestBlockInPlace(t *testing.T) {
	for _, tc := range blockFixtures {
		for _, decrypt := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/decrypt_%t", tc.name, decrypt), func(t *testing.T) {
				block := newExerciseBlock(t, keyHex(t, tc.key))
				input, want := blockHex(t, tc.plaintext), blockHex(t, tc.ciphertext)
				if decrypt {
					input, want = want, input
				}
				buffer := append(input[:], bytes.Repeat([]byte{0xa5}, 9)...)
				tail := bytes.Clone(buffer[16:])
				blockOperation(block, decrypt)(buffer, buffer)
				if !bytes.Equal(buffer[:16], want[:]) || !bytes.Equal(buffer[16:], tail) {
					t.Fatalf("in-place result = %x; want block %x and unchanged tail %x", buffer, want, tail)
				}
			})
		}
	}
}

func TestBlockBufferBounds(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		t.Run(fmt.Sprintf("decrypt_%t", decrypt), func(t *testing.T) {
			tc := blockFixtures[0]
			block := newExerciseBlock(t, keyHex(t, tc.key))
			input, want := blockHex(t, tc.plaintext), blockHex(t, tc.ciphertext)
			if decrypt {
				input, want = want, input
			}
			src := append(input[:], bytes.Repeat([]byte{0x5a}, 21)...)
			srcBefore := bytes.Clone(src)
			dst := bytes.Repeat([]byte{0xa5}, 39)
			tailBefore := bytes.Clone(dst[16:])
			blockOperation(block, decrypt)(dst, src)
			if !bytes.Equal(dst[:16], want[:]) {
				t.Fatalf("first block = %x, want %x", dst[:16], want)
			}
			if !bytes.Equal(dst[16:], tailBefore) {
				t.Fatal("operation changed bytes after the first destination block")
			}
			if !bytes.Equal(src, srcBefore) {
				t.Fatal("operation changed a separate source buffer")
			}
		})
	}
}

func TestBlockShortBuffers(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		for _, shortSource := range []bool{false, true} {
			for _, size := range []int{-1, 0, 1, 15} {
				t.Run(fmt.Sprintf("decrypt_%t/short_source_%t/len_%d", decrypt, shortSource, size), func(t *testing.T) {
					block := newExerciseBlock(t, keyHex(t, blockFixtures[0].key))
					var short []byte
					if size >= 0 {
						// A large capacity must not make a short length acceptable.
						short = make([]byte, size, 32)
					}
					dst, src := short, make([]byte, 16)
					if shortSource {
						dst, src = src, dst
					}
					requireBlockPanic(t, func() { blockOperation(block, decrypt)(dst, src) })
				})
			}
		}
	}
}

func TestBlockOverlap(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		for _, offset := range []int{1, 15, -1, -15} {
			t.Run(fmt.Sprintf("decrypt_%t/partial_offset_%d", decrypt, offset), func(t *testing.T) {
				block := newExerciseBlock(t, keyHex(t, blockFixtures[0].key))
				buffer := make([]byte, 48)
				src, dst := buffer[16:32], buffer[16+offset:32+offset]
				requireBlockPanic(t, func() { blockOperation(block, decrypt)(dst, src) })
			})
		}
		for _, destinationFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("decrypt_%t/disjoint_destination_first_%t", decrypt, destinationFirst), func(t *testing.T) {
				tc := blockFixtures[0]
				block := newExerciseBlock(t, keyHex(t, tc.key))
				input, want := blockHex(t, tc.plaintext), blockHex(t, tc.ciphertext)
				if decrypt {
					input, want = want, input
				}
				buffer := bytes.Repeat([]byte{0xa5}, 48)
				// Whole slices overlap, but the first 16 bytes do not.
				// Matching Go's AES means checking only those active blocks.
				src, dst := buffer[:32], buffer[16:]
				if destinationFirst {
					src, dst = dst, src
				}
				copy(src, input[:])
				tailBefore := bytes.Clone(dst[16:])
				blockOperation(block, decrypt)(dst, src)
				if !bytes.Equal(dst[:16], want[:]) || !bytes.Equal(src[:16], input[:]) {
					t.Fatalf("disjoint blocks: destination=%x, source=%x; want %x, %x", dst[:16], src[:16], want, input)
				}
				if !bytes.Equal(dst[16:], tailBefore) {
					t.Fatal("operation changed bytes after the first destination block")
				}
			})
		}
	}
}

func TestBlockKeyOwnershipAndReuse(t *testing.T) {
	// A cipher fixes its key at construction and does not chain independent
	// calls. Match crypto/aes.NewCipher ownership and cipher.Block semantics.
	for _, tc := range blockFixtures {
		t.Run(tc.name, func(t *testing.T) {
			key := keyHex(t, tc.key)
			original := bytes.Clone(key)
			block := newExerciseBlock(t, key)
			if !bytes.Equal(key, original) {
				t.Fatal("NewCipher changed the caller's key")
			}
			for i := range key {
				key[i] ^= 0xff
			}
			plain, encrypted := blockHex(t, tc.plaintext), blockHex(t, tc.ciphertext)
			var got, unrelated [16]byte
			for i := 0; i < 3; i++ {
				block.Encrypt(got[:], plain[:])
				if got != encrypted {
					t.Fatalf("encryption call %d after caller key mutation: got %x, want %x", i, got, encrypted)
				}
				block.Decrypt(got[:], encrypted[:])
				if got != plain {
					t.Fatalf("decryption call %d after caller key mutation: got %x, want %x", i, got, plain)
				}
				unrelated[0] = byte(i)
				block.Encrypt(got[:], unrelated[:])
				block.Decrypt(got[:], unrelated[:])
			}
		})
	}
}
