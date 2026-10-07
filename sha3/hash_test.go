package sha3

import (
	"bytes"
	stdsha3 "crypto/sha3"
	"fmt"
	"hash"
	"io"
	"testing"
)

// Specification: FIPS 202 (August 2015), sections 4, 5.1 and 6.1.
// Interface contract: Go 1.27.1 hash.Hash and io.Writer.
// https://pkg.go.dev/hash#Hash
// https://pkg.go.dev/io#Writer
// Known answers reuse NIST CAVP CAVS 19.0 (January 2016) fixtures; each
// testdata/sha3_*.json record identifies its .rsp source and case.
// All split-point, ownership and reset cases below are synthetic.

type streamHashVariant struct {
	name        string
	size, rate  int
	newHash     func() hash.Hash
	newStandard func() hash.Hash
}

var streamHashes = []streamHashVariant{
	{"sha3_224", 28, 144, New224, func() hash.Hash { return stdsha3.New224() }},
	{"sha3_256", 32, 136, New256, func() hash.Hash { return stdsha3.New256() }},
	{"sha3_384", 48, 104, New384, func() hash.Hash { return stdsha3.New384() }},
	{"sha3_512", 64, 72, New512, func() hash.Hash { return stdsha3.New512() }},
}

func (v streamHashVariant) want(input []byte) []byte {
	h := v.newStandard()
	h.Write(input)
	return h.Sum(nil)
}

func TestHashMetadata(t *testing.T) {
	for _, v := range streamHashes {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			h := v.newHash()
			for range 2 {
				if h.Size() != v.size || h.BlockSize() != v.rate {
					t.Fatalf("Size/BlockSize = %d/%d, want %d/%d", h.Size(), h.BlockSize(), v.size, v.rate)
				}
				h.Reset()
			}
		})
	}
}

func TestHashWriteContract(t *testing.T) {
	for _, v := range streamHashes {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			h := v.newHash()
			for _, length := range []int{0, 1, v.rate - 1, v.rate, v.rate + 1} {
				backing := streamInput(length + 17)
				before := bytes.Clone(backing)
				writeStream(t, h, backing[:length])
				if !bytes.Equal(backing, before) {
					t.Fatal("Write changed input or spare capacity")
				}
			}
		})
	}
}

func TestHashKnownAnswers(t *testing.T) {
	for _, v := range streamHashes {
		for _, vector := range vectors(t, v.name) {
			t.Run(v.name+"/"+vector.Source+"/"+vector.Case, func(t *testing.T) {
				defer failUnfinished(t)
				h := v.newHash()
				writeStreamChunks(t, h, unhex(t, vector.Message), 7)
				if got, want := h.Sum(nil), unhex(t, vector.Output); !bytes.Equal(got, want) {
					t.Fatalf("streamed digest = %x, want %x", got, want)
				}
			})
		}
	}
}

func TestHashStreaming(t *testing.T) {
	for _, v := range streamHashes {
		for _, length := range []int{0, 1, v.rate - 1, v.rate, v.rate + 1, 2*v.rate - 1, 2 * v.rate, 2*v.rate + 1, 4096} {
			for _, chunk := range []int{1, 7, v.rate - 1, v.rate, v.rate + 1} {
				t.Run(fmt.Sprintf("%s/input=%d/chunk=%d", v.name, length, chunk), func(t *testing.T) {
					defer failUnfinished(t)
					input := streamInput(length)
					h := v.newHash()
					writeStreamChunks(t, h, input, chunk)
					if got, want := h.Sum(nil), v.want(input); !bytes.Equal(got, want) {
						t.Fatalf("streamed digest = %x, want %x", got, want)
					}
				})
			}
		}
	}
}

func TestHashSumPreservesStream(t *testing.T) {
	for _, v := range streamHashes {
		for _, length := range []int{0, v.rate - 1, v.rate, v.rate + 1} {
			for _, spare := range []int{0, v.size - 1, v.size, v.size + 8} {
				t.Run(fmt.Sprintf("%s/input=%d/spare=%d", v.name, length, spare), func(t *testing.T) {
					defer failUnfinished(t)
					input := streamInput(length)
					h := v.newHash()
					writeStreamChunks(t, h, input, 11)
					want := v.want(input)
					b := make([]byte, 3, 3+spare)
					copy(b, []byte{0xa1, 0xb2, 0xc3})
					prefix := bytes.Clone(b)
					out := h.Sum(b)
					if !bytes.Equal(b, prefix) || !bytes.Equal(out, append(bytes.Clone(prefix), want...)) {
						t.Fatalf("Sum did not append the digest while preserving the prefix: %x", out)
					}
					out[len(prefix)] ^= 0xff
					if again := h.Sum(nil); !bytes.Equal(again, want) {
						t.Fatal("Sum changed the stream or returned mutable internal storage")
					}
					extra := []byte("write after Sum")
					writeStream(t, h, extra)
					if got := h.Sum(nil); !bytes.Equal(got, v.want(append(bytes.Clone(input), extra...))) {
						t.Fatal("Write after Sum did not extend the original message")
					}
				})
			}
		}
	}
}

func TestHashEmptySum(t *testing.T) {
	for _, v := range streamHashes {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			h := v.newHash()
			if got := h.Sum(nil); !bytes.Equal(got, v.want(nil)) {
				t.Fatalf("empty digest = %x", got)
			}
			writeStream(t, h, []byte("abc"))
			if got := h.Sum(nil); !bytes.Equal(got, v.want([]byte("abc"))) {
				t.Fatal("empty Sum finalized the running hash")
			}
		})
	}
}

func TestHashReset(t *testing.T) {
	for _, v := range streamHashes {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			h := v.newHash()
			writeStream(t, h, streamInput(v.rate+3))
			h.Reset()
			if !bytes.Equal(h.Sum(nil), v.want(nil)) {
				t.Fatal("Reset did not restore the empty hash")
			}
			input := []byte("message after reset")
			writeStream(t, h, input)
			if !bytes.Equal(h.Sum(nil), v.want(input)) {
				t.Fatal("Reset lost the variant configuration")
			}
			h.Reset()
			if h.Size() != v.size || h.BlockSize() != v.rate || !bytes.Equal(h.Sum(nil), v.want(nil)) {
				t.Fatal("Reset after Sum failed")
			}
		})
	}
}

func TestHashInputOwnership(t *testing.T) {
	for _, v := range streamHashes {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			backing := streamInput(v.rate + 3 + 29)
			before := bytes.Clone(backing)
			h := v.newHash()
			writeStream(t, h, backing[:v.rate+3])
			if !bytes.Equal(backing, before) {
				t.Fatal("Write changed input or spare capacity")
			}
			for i := range backing {
				backing[i] ^= 0xff
			}
			if !bytes.Equal(h.Sum(nil), v.want(before[:v.rate+3])) {
				t.Fatal("Write retained caller-owned input")
			}
		})
	}
}

func TestHashIndependentInstances(t *testing.T) {
	for _, v := range streamHashes {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			a, b := v.newHash(), v.newHash()
			writeStream(t, a, []byte("first"))
			writeStream(t, b, []byte("second"))
			a.Reset()
			writeStream(t, a, []byte("third"))
			if !bytes.Equal(a.Sum(nil), v.want([]byte("third"))) ||
				!bytes.Equal(b.Sum(nil), v.want([]byte("second"))) {
				t.Fatal("instances share mutable state")
			}
		})
	}
}

func TestHashReaderIntegration(t *testing.T) {
	for _, v := range streamHashes {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			input := streamInput(3*v.rate + 17)
			h := v.newHash()
			n, err := io.Copy(h, bytes.NewReader(input))
			if err != nil || n != int64(len(input)) || !bytes.Equal(h.Sum(nil), v.want(input)) {
				t.Fatalf("io.Copy: n=%d err=%v", n, err)
			}
		})
	}
}
