package sha1

import (
	"bytes"
	standard "crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"runtime"
	"testing"
)

// All algorithm checks target FIPS 180-4 (2015), sections 5.1.1, 5.3.1, and 6.1.2.
// These two published known answers come from the NIST SHA1.pdf examples:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
// The long example requires two padded blocks.
const longMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

var knownAnswers = []struct{ name, message, digest string }{
	{"abc", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
	{"two_padded_blocks", longMessage, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
}

// Supplementary messages are synthetic. Their oracle is Go's crypto/sha1,
// an independent implementation; they are not published NIST test vectors.
var boundaryLengths = []int{0, 1, 3, 27, 28, 31, 32, 47, 48, 55, 56, 57, 63, 64, 65, 111, 112, 119, 120, 121, 127, 128, 129, 239, 240, 255, 256, 257, 1024, 4097}

var _ hash.Hash = (*digest)(nil)

func testMessage(length int) []byte {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(i*131 + i/7 + 17)
	}
	return data
}

func digestHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 20 {
		t.Fatalf("invalid SHA-1 digest fixture %q: %v", encoded, err)
	}
	return decoded
}

func writeChecked(t *testing.T, h hash.Hash, data []byte) {
	t.Helper()
	if n, err := h.Write(data); n != len(data) || err != nil {
		t.Fatalf("Write returned (%d, %v), want (%d, nil)", n, err, len(data))
	}
}

func checkDigest(t *testing.T, h hash.Hash, data []byte) {
	t.Helper()
	want := standard.Sum(data)
	if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
		t.Fatalf("digest = %x, want %x", got, want)
	}
}

// A placeholder panic must fail its test without preventing streaming tests
// from running. Unexpected non-runtime panics also fail; runtime panics propagate.
func failOnPanic(t *testing.T) {
	t.Helper()
	if recovered := recover(); recovered != nil {
		if _, ok := recovered.(runtime.Error); ok {
			panic(recovered)
		}
		t.Fatalf("unexpected panic: %v", recovered)
	}
}

// This checks fixture transcription only, independently of the learning code.
func TestVectorFixtures(t *testing.T) {
	for _, tc := range knownAnswers {
		t.Run(tc.name, func(t *testing.T) {
			got := standard.Sum([]byte(tc.message))
			if want := digestHex(t, tc.digest); !bytes.Equal(got[:], want) {
				t.Fatalf("fixture disagrees with crypto/sha1: got %x, want %x", got, want)
			}
		})
	}
}

func TestSumKnownAnswers(t *testing.T) {
	for _, tc := range knownAnswers {
		t.Run(tc.name, func(t *testing.T) {
			defer failOnPanic(t)
			got := Sum([]byte(tc.message))
			if want := digestHex(t, tc.digest); !bytes.Equal(got[:], want) {
				t.Fatalf("digest = %x, want %x", got, want)
			}
		})
	}
}

func TestSumDifferential(t *testing.T) {
	defer failOnPanic(t)
	if got, want := Sum(nil), standard.Sum(nil); got != want {
		t.Fatalf("nil digest = %x, want %x", got, want)
	}
	for _, length := range boundaryLengths {
		input := testMessage(length)
		if got, want := Sum(input), standard.Sum(input); got != want {
			t.Fatalf("length %d: digest = %x, want %x", length, got, want)
		}
	}
}

func TestSumInputUnchanged(t *testing.T) {
	defer failOnPanic(t)
	backing := bytes.Repeat([]byte{0xa5}, 512)
	input := backing[8:120]
	copy(input, testMessage(len(input)))
	before := bytes.Clone(backing)
	want := standard.Sum(input)
	for i := 0; i < 2; i++ {
		if got := Sum(input); got != want {
			t.Fatalf("call %d: digest = %x, want %x", i, got, want)
		}
		if !bytes.Equal(backing, before) {
			t.Fatalf("call %d changed the input, prefix, or spare capacity", i)
		}
	}
}

// hash.Hash and io.Writer define the streaming API contract:
// https://pkg.go.dev/hash#Hash
// https://pkg.go.dev/io#Writer
func TestStreamingKnownAnswers(t *testing.T) {
	for _, tc := range knownAnswers {
		t.Run(tc.name, func(t *testing.T) {
			h := New()
			for _, b := range []byte(tc.message) {
				writeChecked(t, h, []byte{b})
			}
			if got, want := h.Sum(nil), digestHex(t, tc.digest); !bytes.Equal(got, want) {
				t.Fatalf("streamed digest = %x, want %x", got, want)
			}
		})
	}
}

func TestStreamingDifferential(t *testing.T) {
	for _, length := range boundaryLengths {
		for _, chunkSize := range []int{1, 7, 55, 56, 63, 64, 65, 128, 4097} {
			t.Run(fmt.Sprintf("length_%d/chunk_%d", length, chunkSize), func(t *testing.T) {
				input := testMessage(length)
				h := New()
				writeChecked(t, h, nil)
				for offset := 0; offset < len(input); offset += chunkSize {
					writeChecked(t, h, input[offset:min(offset+chunkSize, len(input))])
				}
				writeChecked(t, h, []byte{})
				checkDigest(t, h, input)
			})
		}
	}
}

func TestStreamingSplitPoints(t *testing.T) {
	for _, length := range []int{0, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			input := testMessage(length)
			want := standard.Sum(input)
			for split := 0; split <= length; split++ {
				h := New()
				writeChecked(t, h, input[:split])
				writeChecked(t, h, nil)
				writeChecked(t, h, input[split:])
				if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
					t.Fatalf("split %d: digest = %x, want %x", split, got, want)
				}
			}
		})
	}
}

func TestSumPreservesStream(t *testing.T) {
	for _, length := range []int{0, 3, 55, 56, 63, 64, 65, 120, 128} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			input := testMessage(length)
			h := New()
			writeChecked(t, h, input)
			checkDigest(t, h, input)
			checkDigest(t, h, input)
			want := standard.Sum(input)
			for _, spare := range []int{0, 20} {
				prefix := make([]byte, 3, 3+spare)
				copy(prefix, []byte{0xa5, 0x5a, 0xff})
				before := bytes.Clone(prefix)
				wantOutput := append(bytes.Clone(prefix), want[:]...)
				got := h.Sum(prefix)
				if !bytes.Equal(prefix, before) || !bytes.Equal(got, wantOutput) {
					t.Fatalf("Sum(prefix) = %x, want %x; prefix = %x", got, wantOutput, prefix)
				}
				got[len(prefix)] ^= 0xff
				checkDigest(t, h, input)
			}
			suffix := testMessage(73)
			writeChecked(t, h, suffix)
			checkDigest(t, h, append(bytes.Clone(input), suffix...))
		})
	}
}

func TestStreamingInputOwnership(t *testing.T) {
	for _, length := range []int{3, 55, 56, 63, 64, 65, 129} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			backing := bytes.Repeat([]byte{0xa5}, length+128)
			input := backing[8 : 8+length]
			copy(input, testMessage(length))
			before := bytes.Clone(backing)
			want := standard.Sum(input)
			h := New()
			writeChecked(t, h, input)
			if !bytes.Equal(backing, before) {
				t.Fatal("Write modified the input, prefix, or spare capacity")
			}
			for i := range backing {
				backing[i] ^= 0xff
			}
			if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Fatalf("Write retained caller storage: digest = %x, want %x", got, want)
			}
		})
	}
}

func TestResetAndMetadata(t *testing.T) {
	if size != 20 || blockSize != 64 {
		t.Fatalf("Size/BlockSize constants = %d/%d, want 20/64", size, blockSize)
	}
	h := New()
	for _, length := range []int{0, 3, 56, 64, 65, 129} {
		if h.Size() != 20 || h.BlockSize() != 64 {
			t.Fatalf("Size/BlockSize methods = %d/%d, want 20/64", h.Size(), h.BlockSize())
		}
		input := testMessage(length)
		writeChecked(t, h, input)
		checkDigest(t, h, input)
		h.Reset()
		checkDigest(t, h, nil)
		h.Reset()
	}
}

// FIPS 180-4 (2015) section 5.3.1: every new or reset instance starts at the IV.
func TestInstanceIsolation(t *testing.T) {
	input := testMessage(129)
	first, second := New(), New()
	writeChecked(t, first, input[:63])
	writeChecked(t, second, input[:65])
	third := New()
	writeChecked(t, third, input)
	third.Reset()
	writeChecked(t, second, input[65:])
	writeChecked(t, first, input[63:])
	checkDigest(t, first, input)
	checkDigest(t, second, input)
	checkDigest(t, third, nil)
}

// io.Reader allows bytes together with io.EOF. Returning short reads also
// exercises io.CopyBuffer's reuse of its buffer across multiple hash writes.
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
	input := testMessage(4097)
	h := New()
	n, err := io.CopyBuffer(h, &chunkReader{data: input}, make([]byte, 65))
	if err != nil || n != int64(len(input)) {
		t.Fatalf("io.CopyBuffer returned (%d, %v), want (%d, nil)", n, err, len(input))
	}
	checkDigest(t, h, input)
}

// FIPS 180-4 (2015) sections 5.1.1 and 6.1 allow fewer than 2^64 bits,
// hence at most 2^61-1 whole bytes. This learning API rejects overflow by panic.
// Synthetic internal states test counting and finalization without allocating
// exabytes. They do not verify the digest of a real message at the length limit.
func TestStreamingLengthLimit(t *testing.T) {
	const limit uint64 = (1 << 61) - 1
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
			d := New()
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
			if got := d.Sum(nil); len(got) != 20 {
				t.Fatalf("digest length at limit = %d, want 20", len(got))
			}
			if *d != snapshot {
				t.Fatal("Sum at the length limit changed the live state")
			}
		})
	}
}

// Fixed padding isolates schedule and compression from the padding implementation.
func abcBlock() [64]byte { return [64]byte{0: 0x61, 1: 0x62, 2: 0x63, 3: 0x80, 63: 0x18} }

// Checkpoints independently derived from FIPS 180-4 (2015) section 6.1.2, step 1.
// These are supplementary checkpoints, not separately published NIST vectors.
func TestSchedule(t *testing.T) {
	got := schedule(abcBlock())
	for i := 1; i < 15; i++ {
		if got[i] != 0 {
			t.Errorf("W[%d] = %08x, want 0", i, got[i])
		}
	}
	for i, want := range map[int]uint32{
		0: 0x61626380, 15: 0x00000018, 16: 0xc2c4c700, 17: 0x00000000,
		18: 0x00000030, 19: 0x85898e01, 31: 0x5898e048, 63: 0x627b49a1, 79: 0x822e0879,
	} {
		if got[i] != want {
			t.Errorf("W[%d] = %08x, want %08x", i, got[i], want)
		}
	}
	if got := schedule([64]byte{}); got != [80]uint32{} {
		t.Fatal("zero-block schedule is not all zero")
	}
}

// FIPS 180-4 (2015) sections 5.3.1 and 6.1.2: the NIST abc digest is the state
// after one compression, including feed-forward. Literal IV words are independent
// of the production initialState table.
func TestCompress(t *testing.T) {
	state := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	compress(&state, abcBlock())
	want := [5]uint32{0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d}
	if state != want {
		t.Fatalf("compressed state = %08x, want %08x", state, want)
	}
}

// FIPS 180-4 (2015) sections 5.1.1 and 6.1.2: synthetic messages and chunk
// patterns are compared with crypto/sha1, not treated as published vectors.
func FuzzStreamingAgainstStandard(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte("abc"), []byte{0})
	f.Add(testMessage(55), []byte{6, 12})
	f.Add(testMessage(56), []byte{54, 0})
	f.Add(testMessage(64), []byte{63})
	f.Add(testMessage(129), []byte{62, 0, 64})
	f.Fuzz(func(t *testing.T, input, pattern []byte) {
		before := bytes.Clone(input)
		h := New()
		writeChecked(t, h, nil)
		for offset, part := 0, 0; offset < len(input); part++ {
			chunk := 64
			if len(pattern) != 0 {
				chunk = int(pattern[part%len(pattern)]) + 1
			}
			end := min(offset+chunk, len(input))
			writeChecked(t, h, input[offset:end])
			offset = end
		}
		checkDigest(t, h, input)
		if !bytes.Equal(input, before) {
			t.Fatal("hashing modified the fuzz input")
		}
		suffix := []byte("suffix after Sum")
		writeChecked(t, h, suffix)
		checkDigest(t, h, append(bytes.Clone(input), suffix...))
	})
}
