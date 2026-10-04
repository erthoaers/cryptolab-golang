package sha256

import (
	"bytes"
	standard "crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"runtime"
	"testing"
)

// The two fixed known-answer tests come from NIST SHA256.pdf, verified on 2026-10-02.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
var knownAnswers = []struct {
	name, message, digest string
}{
	{"abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	{"two_blocks", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
}

func decodeDigest(t *testing.T, encoded string) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("invalid digest fixture %q: %v", encoded, err)
	}
	var digest [32]byte
	copy(digest[:], decoded)
	return digest
}

// This test checks only the fixed vector transcription without calling the exercise implementation.
func TestVectorFixtures(t *testing.T) {
	for _, vector := range knownAnswers {
		t.Run(vector.name, func(t *testing.T) {
			want := decodeDigest(t, vector.digest)
			if got := standard.Sum256([]byte(vector.message)); got != want {
				t.Fatalf("NIST fixture disagrees with the standard library: got %x, want %x", got, want)
			}
		})
	}
}

func TestSum256KnownAnswers(t *testing.T) {
	for _, vector := range knownAnswers {
		t.Run(vector.name, func(t *testing.T) {
			want := decodeDigest(t, vector.digest)
			if got := Sum256([]byte(vector.message)); got != want {
				t.Fatalf("digest: got %x, want %x", got, want)
			}
		})
	}
}

func TestSum256Differential(t *testing.T) {
	for _, length := range []int{0, 1, 3, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257, 1024, 4097} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			input := make([]byte, length)
			for i := range input {
				input[i] = byte(i*131 + i/7 + 17)
			}
			want := standard.Sum256(input)
			if got := Sum256(input); got != want {
				t.Fatalf("result disagrees with the standard library: got %x, want %x", got, want)
			}
		})
	}
	t.Run("nil", func(t *testing.T) {
		if got, want := Sum256(nil), standard.Sum256(nil); got != want {
			t.Fatalf("nil digest: got %x, want %x", got, want)
		}
	})
}

func TestSum256InputUnchanged(t *testing.T) {
	backing := bytes.Repeat([]byte{0xa5}, 256)
	input := backing[8:64]
	for i := range input {
		input[i] = byte(i)
	}
	before := bytes.Clone(backing)
	want := standard.Sum256(input)
	first := Sum256(input)
	if !bytes.Equal(backing, before) {
		t.Fatal("Sum256 modified the input, its prefix, or its spare capacity")
	}
	second := Sum256(input)
	if first != want || second != want {
		t.Fatalf("repeated calls must return consistent results: first %x, second %x, want %x", first, second, want)
	}
	if !bytes.Equal(backing, before) {
		t.Fatal("the second Sum256 call modified the backing array")
	}
}

func FuzzSum256AgainstStandard(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("abc"))
	f.Add([]byte(knownAnswers[1].message))
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, input []byte) {
		before := bytes.Clone(input)
		want := standard.Sum256(input)
		got := Sum256(input)
		if !bytes.Equal(input, before) {
			t.Fatal("Sum256 modified the input")
		}
		if got != want {
			t.Fatalf("result disagrees with the standard library: got %x, want %x", got, want)
		}
	})
}

// Algorithm edition for the tests below: FIPS 180-4 (August 2015).
// Padding and block processing: sections 5.1.1, 5.2.1, and 6.2.2.
// SHA-224 initialization and output: sections 5.3.2 and 6.3.
// SHA-224 known answers: the locally archived NIST SHA224.pdf examples.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
var knownAnswers224 = []struct{ name, message, digest string }{
	{"abc", "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
	{"two_blocks", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"},
}

func decodeDigest224(t *testing.T, encoded string) [28]byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 28 {
		t.Fatalf("invalid SHA-224 digest fixture %q: %v", encoded, err)
	}
	var digest [28]byte
	copy(digest[:], decoded)
	return digest
}

// Fixture verification is separate from acceptance of the learner's implementation.
func TestSum224VectorFixtures(t *testing.T) {
	for _, vector := range knownAnswers224 {
		t.Run(vector.name, func(t *testing.T) {
			if got, want := standard.Sum224([]byte(vector.message)), decodeDigest224(t, vector.digest); got != want {
				t.Fatalf("NIST fixture disagrees with the standard library: got %x, want %x", got, want)
			}
		})
	}
}

func TestSum224KnownAnswers(t *testing.T) {
	for _, vector := range knownAnswers224 {
		t.Run(vector.name, func(t *testing.T) {
			input := []byte(vector.message)
			want := decodeDigest224(t, vector.digest)
			if got := Sum224(input); got != want {
				t.Fatalf("SHA-224 digest = %x, want %x", got, want)
			}
			h := New224()
			writeChecked(t, h, input[:1])
			writeChecked(t, h, input[1:])
			if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Fatalf("streamed SHA-224 digest = %x, want %x", got, want)
			}
		})
	}
}

type hashVariant struct {
	name    string
	newHash func() hash.Hash
	oracle  func() hash.Hash
	oneShot func([]byte) []byte
	size    int
}

var hashVariants = []hashVariant{
	{"SHA256", New, standard.New, func(p []byte) []byte { sum := Sum256(p); return sum[:] }, 32},
	{"SHA224", New224, standard.New224, func(p []byte) []byte { sum := Sum224(p); return sum[:] }, 28},
}

// Synthetic cases supplement the NIST examples; expected digests come from
// Go's independent crypto/sha256 implementation, not from this package.
var boundaryLengths = []int{0, 1, 3, 27, 28, 31, 32, 55, 56, 57, 63, 64, 65, 111, 112, 119, 120, 127, 128, 129, 255, 256, 257, 1024, 4097}

func testMessage(length int) []byte {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(i*131 + i/7 + 17)
	}
	return data
}

func writeChecked(t testing.TB, h hash.Hash, p []byte) {
	t.Helper()
	if n, err := h.Write(p); n != len(p) || err != nil {
		t.Fatalf("Write returned (%d, %v), want (%d, nil)", n, err, len(p))
	}
}

func referenceDigest(t testing.TB, v hashVariant, input []byte) []byte {
	t.Helper()
	h := v.oracle()
	writeChecked(t, h, input)
	return h.Sum(nil)
}

func TestSum224Differential(t *testing.T) {
	for _, length := range boundaryLengths {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			input := testMessage(length)
			if got, want := Sum224(input), standard.Sum224(input); got != want {
				t.Fatalf("SHA-224 digest = %x, want %x", got, want)
			}
		})
	}
	if got, want := Sum224(nil), standard.Sum224(nil); got != want {
		t.Fatalf("nil SHA-224 digest = %x, want %x", got, want)
	}
}

func TestSum224InputUnchanged(t *testing.T) {
	backing := bytes.Repeat([]byte{0xa5}, 256)
	input := backing[8:120]
	copy(input, testMessage(len(input)))
	before := bytes.Clone(backing)
	want := standard.Sum224(input)
	for i := 0; i < 2; i++ {
		if got := Sum224(input); got != want {
			t.Fatalf("call %d: digest = %x, want %x", i, got, want)
		}
		if !bytes.Equal(backing, before) {
			t.Fatalf("call %d changed the input, prefix, or spare capacity", i)
		}
	}
}

// hash.Hash and io.Writer define the API behavior exercised by the streaming tests.
// https://pkg.go.dev/hash#Hash
// https://pkg.go.dev/io#Writer
// The digest oracle remains FIPS 180-4 (2015), sections 6.2 and 6.3.
func TestStreamingDifferential(t *testing.T) {
	for _, v := range hashVariants {
		t.Run(v.name, func(t *testing.T) {
			for _, length := range boundaryLengths {
				input := testMessage(length)
				want := referenceDigest(t, v, input)
				for _, chunkSize := range []int{1, 7, 55, 56, 63, 64, 65, 128, 4097} {
					t.Run(fmt.Sprintf("length_%d/chunk_%d", length, chunkSize), func(t *testing.T) {
						h := v.newHash()
						writeChecked(t, h, nil)
						for offset := 0; offset < len(input); offset += chunkSize {
							end := min(offset+chunkSize, len(input))
							writeChecked(t, h, input[offset:end])
						}
						writeChecked(t, h, []byte{})
						if got := h.Sum(nil); !bytes.Equal(got, want) {
							t.Fatalf("streamed digest = %x, want %x", got, want)
						}
					})
				}
			}
		})
	}
}

func TestStreamingSplitPoints(t *testing.T) {
	for _, v := range hashVariants {
		t.Run(v.name, func(t *testing.T) {
			for _, length := range []int{0, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129} {
				input := testMessage(length)
				want := referenceDigest(t, v, input)
				for split := 0; split <= length; split++ {
					h := v.newHash()
					writeChecked(t, h, input[:split])
					writeChecked(t, h, input[split:])
					if got := h.Sum(nil); !bytes.Equal(got, want) {
						t.Fatalf("length %d, split %d: digest = %x, want %x", length, split, got, want)
					}
				}
			}
		})
	}
}

func TestSumPreservesStream(t *testing.T) {
	for _, v := range hashVariants {
		t.Run(v.name, func(t *testing.T) {
			for _, length := range []int{0, 3, 55, 56, 63, 64, 65, 120, 128} {
				t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
					input := testMessage(length)
					h := v.newHash()
					writeChecked(t, h, input)
					want := referenceDigest(t, v, input)
					for i := 0; i < 2; i++ {
						if got := h.Sum(nil); !bytes.Equal(got, want) {
							t.Fatalf("Sum call %d: digest = %x, want %x", i, got, want)
						}
					}
					for _, spare := range []int{0, v.size} {
						prefix := make([]byte, 3, 3+spare)
						copy(prefix, []byte{0xa5, 0x5a, 0xff})
						wantPrefix := bytes.Clone(prefix)
						wantOutput := append(bytes.Clone(prefix), want...)
						got := h.Sum(prefix)
						if !bytes.Equal(prefix, wantPrefix) || !bytes.Equal(got, wantOutput) {
							t.Fatalf("Sum(prefix) = %x, want %x; prefix = %x", got, wantOutput, prefix)
						}
						got[len(prefix)] ^= 0xff
						if again := h.Sum(nil); !bytes.Equal(again, want) {
							t.Fatal("modifying a returned digest changed the hash state")
						}
					}
					suffix := testMessage(73)
					writeChecked(t, h, suffix)
					joined := append(bytes.Clone(input), suffix...)
					if got, expected := h.Sum(nil), referenceDigest(t, v, joined); !bytes.Equal(got, expected) {
						t.Fatalf("Write after Sum: digest = %x, want %x", got, expected)
					}
				})
			}
		})
	}
}

func TestStreamingInputOwnership(t *testing.T) {
	for _, v := range hashVariants {
		t.Run(v.name, func(t *testing.T) {
			for _, length := range []int{3, 55, 56, 63, 64, 65, 129} {
				t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
					backing := bytes.Repeat([]byte{0xa5}, length+128)
					input := backing[8 : 8+length]
					copy(input, testMessage(length))
					before := bytes.Clone(backing)
					want := referenceDigest(t, v, input)
					h := v.newHash()
					writeChecked(t, h, input)
					if !bytes.Equal(backing, before) {
						t.Fatal("Write modified the input, prefix, or spare capacity")
					}
					for i := range backing {
						backing[i] ^= 0xff
					}
					if got := h.Sum(nil); !bytes.Equal(got, want) {
						t.Fatalf("Write retained caller storage: digest = %x, want %x", got, want)
					}
				})
			}
		})
	}
}

func TestResetAndMetadata(t *testing.T) {
	for _, v := range hashVariants {
		t.Run(v.name, func(t *testing.T) {
			h := v.newHash()
			for _, length := range []int{0, 3, 56, 64, 65, 129} {
				if h.Size() != v.size || h.BlockSize() != 64 {
					t.Fatalf("Size/BlockSize = %d/%d, want %d/64", h.Size(), h.BlockSize(), v.size)
				}
				input := testMessage(length)
				writeChecked(t, h, input)
				if got, want := h.Sum(nil), referenceDigest(t, v, input); !bytes.Equal(got, want) {
					t.Fatalf("length %d after Reset: digest = %x, want %x", length, got, want)
				}
				h.Reset()
				if got, want := h.Sum(nil), referenceDigest(t, v, nil); !bytes.Equal(got, want) {
					t.Fatalf("Reset did not restore the empty-message digest: got %x, want %x", got, want)
				}
			}
		})
	}
}

// FIPS 180-4 sections 5.3.2 and 5.3.3 require independent variant-specific IVs.
func TestVariantIsolation(t *testing.T) {
	input := testMessage(129)
	first, second, third := New(), New224(), New()
	writeChecked(t, first, input[:63])
	writeChecked(t, second, input[:55])
	writeChecked(t, third, []byte("abc"))
	third.Reset()
	_ = Sum224(input)
	_ = Sum256(input)
	writeChecked(t, second, input[55:])
	writeChecked(t, first, input[63:])
	for _, tc := range []struct {
		name string
		hash hash.Hash
		want []byte
	}{
		{"SHA256", first, referenceDigest(t, hashVariants[0], input)},
		{"SHA224", second, referenceDigest(t, hashVariants[1], input)},
		{"reset_SHA256", third, referenceDigest(t, hashVariants[0], nil)},
	} {
		if got := tc.hash.Sum(nil); !bytes.Equal(got, tc.want) {
			t.Fatalf("%s state was affected by another instance: got %x, want %x", tc.name, got, tc.want)
		}
	}
}

// This reader reuses caller storage and returns data together with io.EOF.
// io.Reader permits that final read; the hash must receive those bytes too.
type chunkReader struct{ data []byte }

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	n := min(len(p), len(r.data), 17)
	copy(p[:n], r.data[:n])
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestReaderIntegration(t *testing.T) {
	for _, v := range hashVariants {
		t.Run(v.name, func(t *testing.T) {
			input := testMessage(4097)
			h := v.newHash()
			n, err := io.CopyBuffer(h, &chunkReader{data: input}, make([]byte, 65))
			if err != nil || n != int64(len(input)) {
				t.Fatalf("io.CopyBuffer returned (%d, %v), want (%d, nil)", n, err, len(input))
			}
			if got, want := h.Sum(nil), referenceDigest(t, v, input); !bytes.Equal(got, want) {
				t.Fatalf("reader digest = %x, want %x", got, want)
			}
		})
	}
}

// FIPS 180-4 sections 6.2 and 6.3 require bit lengths below 2^64.
// Whole-byte input therefore permits at most 2^61-1 bytes.
// These synthetic internal states test counting, rejection, and finalization only;
// they do not claim to verify the digest of an actual exabyte-scale message.
// This learning API deliberately panics before accepting any over-limit input.
func TestStreamingLengthLimit(t *testing.T) {
	const limit uint64 = (1 << 61) - 1
	for _, v := range hashVariants {
		t.Run(v.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				before uint64
				input  int
				panic  bool
			}{
				{"accept_last_byte", limit - 1, 1, false},
				{"accept_full_block", limit - 64, 64, false},
				{"accept_empty_at_limit", limit, 0, false},
				{"reject_one_byte", limit, 1, true},
				{"reject_whole_write", limit - 2, 3, true},
				{"reject_before_compressing", limit - 63, 64, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					d := v.newHash().(*digest256)
					d.totalbytes = tc.before
					d.buffered = int(tc.before % 64)
					copy(d.buffer[:], testMessage(64))
					before := *d
					var recovered any
					var n int
					var err error
					func() {
						defer func() { recovered = recover() }()
						n, err = d.Write(testMessage(tc.input))
					}()
					if tc.panic {
						if recovered == nil {
							t.Fatalf("over-limit Write returned (%d, %v) instead of panicking", n, err)
						}
						if _, unexpected := recovered.(runtime.Error); unexpected {
							t.Fatalf("unexpected runtime panic instead of length rejection: %v", recovered)
						}
						if *d != before {
							t.Fatal("rejected Write changed the hash state, buffer, or counter")
						}
						return
					}
					if recovered != nil || err != nil || n != tc.input {
						t.Fatalf("valid Write: n=%d, err=%v, panic=%v", n, err, recovered)
					}
					if d.totalbytes != limit {
						t.Fatalf("total bytes = %d, want %d", d.totalbytes, limit)
					}
					snapshot := *d
					if got := d.Sum(nil); len(got) != v.size {
						t.Fatalf("digest length at limit = %d, want %d", len(got), v.size)
					}
					if *d != snapshot {
						t.Fatal("Sum at the length limit changed the live state")
					}
				})
			}
		})
	}
}

// Checkpoints independently derived from FIPS 180-4 section 6.2.2, step 1.
// These are supplementary checkpoints, not separately published NIST vectors.
func TestSchedule256(t *testing.T) {
	block := [64]byte{0: 0x61, 1: 0x62, 2: 0x63, 3: 0x80, 63: 0x18}
	got := schedule256(block)
	for i := 1; i < 15; i++ {
		if got[i] != 0 {
			t.Errorf("W[%d] = %08x, want 0", i, got[i])
		}
	}
	for i, want := range map[int]uint32{
		0: 0x61626380, 15: 0x00000018, 16: 0x61626380,
		17: 0x000f0000, 18: 0x7da86405, 31: 0xd3b7973b, 63: 0x12b1edeb,
	} {
		if got[i] != want {
			t.Errorf("W[%d] = %08x, want %08x", i, got[i], want)
		}
	}
	if zero := schedule256([64]byte{}); zero != [64]uint32{} {
		t.Fatal("zero-block schedule is not all zero")
	}
}

// FIPS 180-4 sections 5.3.3 and 6.2.2: the NIST SHA256.pdf abc example
// contains one padded block, so its digest is the state including feed-forward.
// Literal IV and padded bytes isolate compression from constructors and padding.
func TestCompress256(t *testing.T) {
	state := [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	block := [64]byte{0: 0x61, 1: 0x62, 2: 0x63, 3: 0x80, 63: 0x18}
	compress256(&state, block)
	want := [8]uint32{
		0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
		0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
	}
	if state != want {
		t.Fatalf("compressed state = %08x, want %08x", state, want)
	}
}

// FIPS 180-4 sections 5.1.1, 6.2, and 6.3; synthetic messages and split patterns
// are checked against crypto/sha256, not treated as published standard vectors.
func FuzzStreamingAgainstStandard(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte("abc"), []byte{0})
	f.Add(testMessage(55), []byte{6, 12})
	f.Add(testMessage(56), []byte{54, 0})
	f.Add(testMessage(64), []byte{63})
	f.Add(testMessage(129), []byte{62, 0, 64})
	f.Fuzz(func(t *testing.T, input, pattern []byte) {
		before := bytes.Clone(input)
		for _, v := range hashVariants {
			h := v.newHash()
			writeChecked(t, h, nil)
			for offset, part := 0, 0; offset < len(input); part++ {
				chunk := 64
				if len(pattern) != 0 {
					chunk = int(pattern[part%len(pattern)]) + 1
				}
				end := offset + min(chunk, len(input)-offset)
				writeChecked(t, h, input[offset:end])
				offset = end
			}
			want := referenceDigest(t, v, before)
			if got := h.Sum(nil); !bytes.Equal(got, want) {
				t.Fatalf("%s streamed digest = %x, want %x", v.name, got, want)
			}
			if got := v.oneShot(input); !bytes.Equal(got, want) {
				t.Fatalf("%s one-shot digest = %x, want %x", v.name, got, want)
			}
			if !bytes.Equal(input, before) {
				t.Fatalf("%s changed the input", v.name)
			}
		}
	})
}
