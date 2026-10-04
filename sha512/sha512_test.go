package sha512

import (
	"bytes"
	standard "crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"runtime"
	"testing"
)

// Algorithm edition: FIPS 180-4 (2015), sections 5.1.2, 5.3.4-5.3.6, and 6.4-6.7.
// Known answers are the abc and 112-byte examples from NIST:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
// The fixed digests below are transcribed from these NIST examples.
const longMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

type variant struct {
	name        string
	newHash     func() hash.Hash
	sum, oracle func([]byte) []byte
	size        int
	digests     [2]string
}

var variants = []variant{
	{name: "SHA384", newHash: New384, size: 48,
		sum:     func(data []byte) []byte { digest := Sum384(data); return digest[:] },
		oracle:  func(data []byte) []byte { digest := standard.Sum384(data); return digest[:] },
		digests: [2]string{"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"},
	},
	{name: "SHA512", newHash: New, size: 64,
		sum:     func(data []byte) []byte { digest := Sum512(data); return digest[:] },
		oracle:  func(data []byte) []byte { digest := standard.Sum512(data); return digest[:] },
		digests: [2]string{"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
	},
	{name: "SHA512_224", newHash: New512_224, size: 28,
		sum:     func(data []byte) []byte { digest := Sum512_224(data); return digest[:] },
		oracle:  func(data []byte) []byte { digest := standard.Sum512_224(data); return digest[:] },
		digests: [2]string{"4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa", "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"},
	},
	{name: "SHA512_256", newHash: New512_256, size: 32,
		sum:     func(data []byte) []byte { digest := Sum512_256(data); return digest[:] },
		oracle:  func(data []byte) []byte { digest := standard.Sum512_256(data); return digest[:] },
		digests: [2]string{"53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"},
	},
}

var _ hash.Hash = (*digest512)(nil)

// Synthetic messages target padding and block boundaries from section 5.1.2.
// Expected digests come from crypto/sha512, not published NIST test vectors.
var boundaryLengths = []int{0, 1, 3, 27, 28, 31, 32, 47, 48, 63, 64, 65, 110, 111, 112, 113, 119, 120, 127, 128, 129, 238, 239, 240, 241, 255, 256, 257, 1024, 4097}

func testMessage(length int) []byte {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(i*131 + i/7 + 17)
	}
	return data
}

func digestHex(t *testing.T, encoded string, size int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != size {
		t.Fatalf("invalid %d-byte digest fixture %q: %v", size, encoded, err)
	}
	return decoded
}

func writeChecked(t *testing.T, h hash.Hash, data []byte) {
	t.Helper()
	if n, err := h.Write(data); n != len(data) || err != nil {
		t.Fatalf("Write returned (%d, %v), want (%d, nil)", n, err, len(data))
	}
}

func checkDigest(t *testing.T, h hash.Hash, v variant, input []byte) {
	t.Helper()
	if got, want := h.Sum(nil), v.oracle(input); !bytes.Equal(got, want) {
		t.Fatalf("digest = %x, want %x", got, want)
	}
}

// Fixture transcription is checked independently of the learning implementation.
func TestVectorFixtures(t *testing.T) {
	for _, v := range variants {
		for i, message := range []string{"abc", longMessage} {
			t.Run(fmt.Sprintf("%s/example_%d", v.name, i), func(t *testing.T) {
				if got, want := v.oracle([]byte(message)), digestHex(t, v.digests[i], v.size); !bytes.Equal(got, want) {
					t.Fatalf("fixture disagrees with crypto/sha512: got %x, want %x", got, want)
				}
			})
		}
	}
}

func TestKnownAnswers(t *testing.T) {
	for _, v := range variants {
		for i, message := range []string{"abc", longMessage} {
			t.Run(fmt.Sprintf("%s/example_%d", v.name, i), func(t *testing.T) {
				want := digestHex(t, v.digests[i], v.size)
				if got := v.sum([]byte(message)); !bytes.Equal(got, want) {
					t.Errorf("one-shot digest = %x, want %x", got, want)
				}
				h := v.newHash()
				for _, b := range []byte(message) {
					writeChecked(t, h, []byte{b})
				}
				if got := h.Sum(nil); !bytes.Equal(got, want) {
					t.Errorf("streamed digest = %x, want %x", got, want)
				}
			})
		}
	}
}

func TestSumDifferential(t *testing.T) {
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			if got, want := v.sum(nil), v.oracle(nil); !bytes.Equal(got, want) {
				t.Fatalf("nil digest = %x, want %x", got, want)
			}
			for _, length := range boundaryLengths {
				input := testMessage(length)
				if got, want := v.sum(input), v.oracle(input); !bytes.Equal(got, want) {
					t.Fatalf("length %d: digest = %x, want %x", length, got, want)
				}
			}
		})
	}
}

func TestSumInputUnchanged(t *testing.T) {
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			backing := bytes.Repeat([]byte{0xa5}, 512)
			input := backing[8:120]
			copy(input, testMessage(len(input)))
			before := bytes.Clone(backing)
			want := v.oracle(input)
			for i := 0; i < 2; i++ {
				if got := v.sum(input); !bytes.Equal(got, want) {
					t.Fatalf("call %d: digest = %x, want %x", i, got, want)
				}
				if !bytes.Equal(backing, before) {
					t.Fatalf("call %d modified the input, prefix, or spare capacity", i)
				}
			}
		})
	}
}

// Streaming behavior follows the hash.Hash and io.Writer contracts:
// https://pkg.go.dev/hash#Hash
// https://pkg.go.dev/io#Writer
func TestStreamingDifferential(t *testing.T) {
	for _, v := range variants {
		for _, length := range boundaryLengths {
			for _, chunk := range []int{1, 7, 111, 112, 127, 128, 129, 256, 4097} {
				t.Run(fmt.Sprintf("%s/length_%d/chunk_%d", v.name, length, chunk), func(t *testing.T) {
					input := testMessage(length)
					h := v.newHash()
					writeChecked(t, h, nil)
					for offset := 0; offset < len(input); offset += chunk {
						writeChecked(t, h, input[offset:min(offset+chunk, len(input))])
					}
					writeChecked(t, h, []byte{})
					checkDigest(t, h, v, input)
				})
			}
		}
	}
}

func TestStreamingSplitPoints(t *testing.T) {
	for _, v := range variants {
		for _, length := range []int{0, 3, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257} {
			t.Run(fmt.Sprintf("%s/length_%d", v.name, length), func(t *testing.T) {
				input := testMessage(length)
				want := v.oracle(input)
				for split := 0; split <= length; split++ {
					h := v.newHash()
					writeChecked(t, h, input[:split])
					writeChecked(t, h, nil)
					writeChecked(t, h, input[split:])
					if got := h.Sum(nil); !bytes.Equal(got, want) {
						t.Fatalf("split %d: digest = %x, want %x", split, got, want)
					}
				}
			})
		}
	}
}

func TestSumPreservesStream(t *testing.T) {
	for _, v := range variants {
		for _, length := range []int{0, 3, 111, 112, 127, 128, 129, 240, 256} {
			t.Run(fmt.Sprintf("%s/length_%d", v.name, length), func(t *testing.T) {
				input := testMessage(length)
				h := v.newHash()
				writeChecked(t, h, input)
				snapshot := *h.(*digest512)
				checkDigest(t, h, v, input)
				checkDigest(t, h, v, input)
				for _, spare := range []int{0, v.size} {
					prefix := make([]byte, 3, 3+spare)
					copy(prefix, []byte{0xa5, 0x5a, 0xff})
					before := bytes.Clone(prefix)
					want := append(bytes.Clone(prefix), v.oracle(input)...)
					got := h.Sum(prefix)
					if !bytes.Equal(prefix, before) || !bytes.Equal(got, want) {
						t.Fatalf("Sum(prefix) = %x, want %x; prefix = %x", got, want, prefix)
					}
					got[len(prefix)] ^= 0xff
					checkDigest(t, h, v, input)
				}
				if *h.(*digest512) != snapshot {
					t.Fatal("Sum changed the live state, buffer, counter, or variant")
				}
				suffix := testMessage(137)
				writeChecked(t, h, suffix)
				checkDigest(t, h, v, append(bytes.Clone(input), suffix...))
			})
		}
	}
}

func TestStreamingInputOwnership(t *testing.T) {
	for _, v := range variants {
		for _, length := range []int{3, 111, 112, 127, 128, 129, 257} {
			t.Run(fmt.Sprintf("%s/length_%d", v.name, length), func(t *testing.T) {
				backing := bytes.Repeat([]byte{0xa5}, length+256)
				input := backing[8 : 8+length]
				copy(input, testMessage(length))
				before := bytes.Clone(backing)
				want := v.oracle(input)
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
	}
}

func TestResetAndMetadata(t *testing.T) {
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			h := v.newHash()
			for _, length := range []int{0, 3, 112, 128, 129, 257} {
				if h.Size() != v.size || h.BlockSize() != 128 {
					t.Fatalf("Size/BlockSize = %d/%d, want %d/128", h.Size(), h.BlockSize(), v.size)
				}
				input := testMessage(length)
				writeChecked(t, h, input)
				checkDigest(t, h, v, input)
				h.Reset()
				checkDigest(t, h, v, nil)
				h.Reset()
			}
			// Reset must clear both counter words even after a synthetic long stream.
			d := h.(*digest512)
			d.totalBytesHigh, d.totalBytesLow, d.buffered = 17, 127, 127
			copy(d.buffer[:], testMessage(128))
			h.Reset()
			if d.totalBytesHigh != 0 || d.totalBytesLow != 0 || d.buffered != 0 {
				t.Fatal("Reset did not clear both length words and the buffered count")
			}
			checkDigest(t, h, v, nil)
			writeChecked(t, h, []byte("abc"))
			checkDigest(t, h, v, []byte("abc"))
		})
	}
}

// FIPS 180-4 sections 5.3.4-5.3.6 require distinct, independent variant IVs.
func TestVariantIsolation(t *testing.T) {
	input := testMessage(257)
	hashes := make([]hash.Hash, len(variants))
	for i, v := range variants {
		hashes[i] = v.newHash()
		writeChecked(t, hashes[i], input[:113+i])
		other := v.newHash()
		writeChecked(t, other, input)
		other.Reset()
		checkDigest(t, other, v, nil)
		if got, want := v.sum(input), v.oracle(input); !bytes.Equal(got, want) {
			t.Fatalf("%s one-shot digest = %x, want %x", v.name, got, want)
		}
	}
	for i, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			writeChecked(t, hashes[i], input[113+i:])
			checkDigest(t, hashes[i], v, input)
		})
	}
}

// io.Reader permits data and io.EOF together. Short reads cause buffer reuse.
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
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			input := testMessage(4097)
			h := v.newHash()
			n, err := io.CopyBuffer(h, &chunkReader{data: input}, make([]byte, 129))
			if err != nil || n != int64(len(input)) {
				t.Fatalf("io.CopyBuffer returned (%d, %v), want (%d, nil)", n, err, len(input))
			}
			checkDigest(t, h, v, input)
		})
	}
}

// FIPS 180-4 sections 6.4-6.7 require fewer than 2^128 bits, or 2^125 bytes.
// math/big is an independent counter oracle. These synthetic states validate
// carries, overflow rejection, and atomicity without allocating huge messages;
// they do not establish an actual exabyte-scale message digest.
func TestLengthAccounting(t *testing.T) {
	const maxLow = ^uint64(0)
	const maxHigh uint64 = (1 << 61) - 1
	limit := new(big.Int).Lsh(big.NewInt(1), 125)
	for _, v := range variants {
		for _, tc := range []struct {
			name      string
			high, low uint64
			input     int
		}{
			{"empty_zero", 0, 0, 0},
			{"last_low_byte", 0, maxLow - 1, 1},
			{"bit_length_crosses_64_bits", 0, (1 << 61) - 1, 1},
			{"carry_at_2_64_bytes", 0, maxLow, 1},
			{"carry_with_multiple_blocks", 7, maxLow - 6, 260},
			{"nonzero_high_word", 17, 101, 31},
			{"carry_to_max_high", maxHigh - 1, maxLow, 1},
			{"last_byte_at_limit", maxHigh, maxLow - 1, 1},
			{"empty_at_limit", maxHigh, maxLow, 0},
			{"reject_one_byte", maxHigh, maxLow, 1},
			{"reject_whole_write", maxHigh, maxLow - 2, 3},
			{"reject_before_compression", maxHigh, maxLow - 126, 128},
		} {
			t.Run(v.name+"/"+tc.name, func(t *testing.T) {
				d := v.newHash().(*digest512)
				d.totalBytesHigh, d.totalBytesLow = tc.high, tc.low
				d.buffered = int(tc.low % 128)
				copy(d.buffer[:], testMessage(128))
				before := *d
				want := new(big.Int).Lsh(new(big.Int).SetUint64(tc.high), 64)
				want.Add(want, new(big.Int).SetUint64(tc.low))
				want.Add(want, big.NewInt(int64(tc.input)))
				var recovered any
				var n int
				var err error
				func() {
					defer func() { recovered = recover() }()
					n, err = d.Write(testMessage(tc.input))
				}()
				if want.Cmp(limit) >= 0 {
					if recovered == nil {
						t.Errorf("over-limit Write returned (%d, %v) instead of panicking", n, err)
					} else if _, unexpected := recovered.(runtime.Error); unexpected {
						t.Errorf("unexpected runtime panic instead of length rejection: %v", recovered)
					}
					if *d != before {
						t.Error("rejected Write changed the hash state, buffer, counter, or variant")
					}
					return
				}
				if recovered != nil || err != nil || n != tc.input {
					t.Fatalf("valid Write: n=%d, err=%v, panic=%v", n, err, recovered)
				}
				wantLow := want.Uint64()
				wantHigh := new(big.Int).Rsh(new(big.Int).Set(want), 64).Uint64()
				if d.totalBytesHigh != wantHigh || d.totalBytesLow != wantLow {
					t.Errorf("byte count = %016x:%016x, want %016x:%016x", d.totalBytesHigh, d.totalBytesLow, wantHigh, wantLow)
				}
				if wantBuffered := int(wantLow % 128); d.buffered != wantBuffered {
					t.Errorf("buffered bytes = %d, want %d", d.buffered, wantBuffered)
				}
				snapshot := *d
				if got := d.Sum(nil); len(got) != v.size {
					t.Errorf("digest length near counter boundary = %d, want %d", len(got), v.size)
				}
				if *d != snapshot {
					t.Error("Sum near the counter boundary changed the live state")
				}
			})
		}
	}
}

// FIPS 180-4 (2015) section 5.1.2; these are synthetic finalization checkpoints,
// not NIST vectors or real huge-message hashes. State starts at the SHA-512 IV;
// the buffered tail is testMessage(low % 128). Golden values were derived using
// arbitrary-precision arithmetic to form the 16-byte length field and Go 1.27.1
// crypto/sha512 to compress those explicitly padded blocks. Raw chaining words
// were extracted before extra padding; empty and 3-byte cases were cross-checked
// with standard.Sum512. Runtime tests do not depend on Go's state serialization.
func TestLengthPadding(t *testing.T) {
	for _, tc := range []struct {
		high, low uint64
		digest    string
	}{
		{0x0000000000000000, 0x0000000000000000, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
		{0x0000000000000000, 0x0000000000000003, "e0be623f2c44a066feb6aeded645b9294c735f675525b3fc1328dc060b235b68a90cbe362f58284748c0ca8c2c14406a1a88523dc5f8446b0090fffb1b60a80c"},
		{0x0000000000000000, 0x1fffffffffffffff, "f5a53255ba53f044328be808f3bbed3667eb39a4ea577d5ee892f1a2a8fe9ff62f5275a7d8281b446662c4c7105ea3367d05a38ec8deb0fe15d051969f8f20ec"},
		{0x0000000000000000, 0x2000000000000000, "4e15588b073f68f07592e9a51190a7e00e2efaaa365fb318f27e82e5c6df94a862d54b825cefcc3bd28977fcefc7fd8cac281f334977797ea395dbff21311a72"},
		{0x0000000000000001, 0x000000000000006f, "96ad4c7bdaab4b6db38159b8be900add6fc33700ac97e761cc693e7d370bebda6ecac3eead718bc437061043d48591190a03b86c55c07e5ca15ebfd2ce49af36"},
		{0x0000000000000001, 0x0000000000000070, "41c61c192a09150f21f52b4cda328c021545c2c11442cc6fac6a7af1892cde70a480636561987f3740fa6ed26335c0de7119bf5362ca8395193c1108690b514e"},
		{0x0000000000000001, 0x000000000000007f, "a3881bfbe2e7bf17ab025dfff137f31dc9ec93ce51824f858820a6b4bfa01eff83b9f82b9c59c1f1cc9ccd404b80adbf65f3bbcdbf6de4c877044d7afe0330a7"},
		{0x1000000000000000, 0xe000000000000001, "024fbb7e9da4d68a0bf8150a9794b1edaed738ca0c87e0ea8329180a49149d7e6f5f82ccbf9ddfbbd5fe8d2923fdb22a88e81e5c070588736e6c5d398f267648"},
		{0x1fffffffffffffff, 0xffffffffffffffff, "db8020dd0905404a9f8655ebea90ea156146a2a85715c97d144bfbe0c83bca39e3beb25207398567e116258c67e52f1e5f82c5c32b0c1e4695035e64afb2b602"},
	} {
		t.Run(fmt.Sprintf("%016x_%016x", tc.high, tc.low), func(t *testing.T) {
			d := New().(*digest512)
			d.totalBytesHigh, d.totalBytesLow = tc.high, tc.low
			d.buffered = int(tc.low % 128)
			copy(d.buffer[:], testMessage(d.buffered))
			before := *d
			if got, want := d.Sum(nil), digestHex(t, tc.digest, 64); !bytes.Equal(got, want) {
				t.Fatalf("length-field finalization = %x, want %x", got, want)
			}
			if *d != before {
				t.Fatal("Sum changed the synthetic live state")
			}
		})
	}
}

// A literal padded block isolates the compression stages from finalization.
func abcBlock() [128]byte {
	return [128]byte{0: 0x61, 1: 0x62, 2: 0x63, 3: 0x80, 127: 0x18}
}

// Supplementary checkpoints independently derived from section 6.4.2, step 1;
// these are not separately published NIST vectors.
func TestSchedule512(t *testing.T) {
	got := schedule512(abcBlock())
	for i := 1; i < 15; i++ {
		if got[i] != 0 {
			t.Errorf("W[%d] = %016x, want 0", i, got[i])
		}
	}
	for i, want := range map[int]uint64{
		0:  0x6162638000000000,
		15: 0x0000000000000018,
		16: 0x6162638000000000,
		17: 0x00030000000000c0,
		18: 0x0a9699a24c700003,
		19: 0x00000c0060000603,
		31: 0x0e987660934142f6,
		63: 0xcc4918b5949206bb,
		79: 0x92aeeed1a7bcf7d2,
	} {
		if got[i] != want {
			t.Errorf("W[%d] = %016x, want %016x", i, got[i], want)
		}
	}
	if zero := schedule512([128]byte{}); zero != [80]uint64{} {
		t.Fatal("zero-block schedule is not all zero")
	}
}

// FIPS 180-4 sections 5.3.5 and 6.4.2: the NIST SHA512.pdf abc example is
// one padded block. Its digest equals the state after compression/feed-forward.
func TestCompress512(t *testing.T) {
	state := [8]uint64{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	compress512(&state, abcBlock())
	want := [8]uint64{
		0xddaf35a193617aba,
		0xcc417349ae204131,
		0x12e6fa4e89a97ea2,
		0x0a9eeee64b55d39a,
		0x2192992a274fc1a8,
		0x36ba3c23a3feebbd,
		0x454d4423643ce80e,
		0x2a9ac94fa54ca49f,
	}
	if state != want {
		t.Fatalf("compressed state = %016x, want %016x", state, want)
	}
}

// FIPS 180-4 sections 5.1.2 and 6.4-6.7; synthetic messages and chunk patterns
// are compared with crypto/sha512. This fuzz target covers ordinary input sizes;
// TestLengthAccounting and TestLengthPadding cover synthetic 128-bit boundaries.
func FuzzStreamingAgainstStandard(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte("abc"), []byte{0})
	f.Add(testMessage(111), []byte{6, 12})
	f.Add(testMessage(112), []byte{110, 0})
	f.Add(testMessage(128), []byte{127})
	f.Add(testMessage(257), []byte{126, 0, 128})
	f.Fuzz(func(t *testing.T, input, pattern []byte) {
		before := bytes.Clone(input)
		for _, v := range variants {
			h := v.newHash()
			writeChecked(t, h, nil)
			for offset, part := 0, 0; offset < len(input); part++ {
				chunk := 128
				if len(pattern) != 0 {
					chunk = int(pattern[part%len(pattern)]) + 1
				}
				end := min(offset+chunk, len(input))
				writeChecked(t, h, input[offset:end])
				offset = end
			}
			checkDigest(t, h, v, input)
			if got, want := v.sum(input), v.oracle(input); !bytes.Equal(got, want) {
				t.Fatalf("%s one-shot digest = %x, want %x", v.name, got, want)
			}
			suffix := []byte("suffix after Sum")
			writeChecked(t, h, suffix)
			checkDigest(t, h, v, append(bytes.Clone(input), suffix...))
		}
		if !bytes.Equal(input, before) {
			t.Fatal("hashing modified the fuzz input")
		}
	})
}
