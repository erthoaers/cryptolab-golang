package sha3

import (
	"bytes"
	stdsha3 "crypto/sha3"
	"fmt"
	"hash"
	"io"
	"testing"
)

// Specification: FIPS 202 (August 2015), sections 4-6 and Appendix A.2.
// Interface contract: Go 1.27.1 hash.XOF, io.Writer, and crypto/sha3.SHAKE.
// https://pkg.go.dev/hash#XOF
// https://pkg.go.dev/crypto/sha3#SHAKE.Read
// Known answers reuse NIST CAVP CAVS 19.0 (January 2016) fixtures; each
// testdata/shake*.json record identifies its .rsp source and case.
// Other cases are synthetic contract/boundary tests, not official vectors.
// Write-after-zero-length-Read matches the installed Go 1.27.1 implementation.

type streamXOFVariant struct {
	name        string
	rate        int
	newXOF      func() hash.XOF
	newStandard func() hash.XOF
}

var streamXOFs = []streamXOFVariant{
	{"shake128", 168, NewSHAKE128, func() hash.XOF { return stdsha3.NewSHAKE128() }},
	{"shake256", 136, NewSHAKE256, func() hash.XOF { return stdsha3.NewSHAKE256() }},
}

func (v streamXOFVariant) want(input []byte, n int) []byte {
	x := v.newStandard()
	x.Write(input)
	out := make([]byte, n)
	x.Read(out)
	return out
}

func TestXOFMetadata(t *testing.T) {
	for _, v := range streamXOFs {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			x := v.newXOF()
			for range 2 {
				if x.BlockSize() != v.rate {
					t.Fatalf("BlockSize = %d, want %d", x.BlockSize(), v.rate)
				}
				x.Reset()
			}
		})
	}
}

func TestXOFWriteContract(t *testing.T) {
	for _, v := range streamXOFs {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			x := v.newXOF()
			for _, length := range []int{0, 1, v.rate - 1, v.rate, v.rate + 1} {
				backing := streamInput(length + 17)
				before := bytes.Clone(backing)
				writeStream(t, x, backing[:length])
				if !bytes.Equal(backing, before) {
					t.Fatal("Write changed input or spare capacity")
				}
			}
		})
	}
}

func TestXOFKnownAnswers(t *testing.T) {
	for _, v := range streamXOFs {
		for _, vector := range vectors(t, v.name) {
			t.Run(v.name+"/"+vector.Source+"/"+vector.Case, func(t *testing.T) {
				defer failUnfinished(t)
				x := v.newXOF()
				writeStreamChunks(t, x, unhex(t, vector.Message), 7)
				want := unhex(t, vector.Output)
				var got []byte
				for len(got) < len(want) {
					got = append(got, readStream(t, x, min(11, len(want)-len(got)))...)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("streamed output = %x, want %x", got, want)
				}
			})
		}
	}
}

func TestXOFStreaming(t *testing.T) {
	for _, v := range streamXOFs {
		for _, length := range []int{0, 1, v.rate - 1, v.rate, v.rate + 1, 2*v.rate + 1, 4096} {
			for _, chunk := range []int{1, 7, v.rate - 1, v.rate, v.rate + 1} {
				t.Run(fmt.Sprintf("%s/input=%d/chunk=%d", v.name, length, chunk), func(t *testing.T) {
					defer failUnfinished(t)
					input := streamInput(length)
					x, oracle := v.newXOF(), v.newStandard()
					writeStreamChunks(t, x, input, chunk)
					writeStream(t, oracle, input)
					// Hit a complete squeeze block, then cross it, with empty reads
					// both before output and at block boundaries.
					for _, n := range []int{0, 1, v.rate - 1, 0, 1, v.rate, v.rate + 1, 2*v.rate + 7} {
						got, want := readStream(t, x, n), readStream(t, oracle, n)
						if !bytes.Equal(got, want) {
							t.Fatalf("next %d output bytes = %x, want %x", n, got, want)
						}
					}
				})
			}
		}
	}
}

func TestXOFReadWithoutWrite(t *testing.T) {
	for _, v := range streamXOFs {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			if got := readStream(t, v.newXOF(), 2*v.rate+3); !bytes.Equal(got, v.want(nil, len(got))) {
				t.Fatal("fresh XOF did not hash the empty message")
			}
		})
	}
}

func TestXOFWriteAfterRead(t *testing.T) {
	for _, v := range streamXOFs {
		for _, n := range []int{0, 1, v.rate, v.rate + 1} {
			for _, write := range [][]byte{nil, {}, []byte("more input")} {
				t.Run(fmt.Sprintf("%s/read=%d/write=%d/nil=%t", v.name, n, len(write), write == nil), func(t *testing.T) {
					defer failUnfinished(t)
					x := v.newXOF()
					writeStream(t, x, []byte("abc"))
					readStream(t, x, n)
					requireStreamPanic(t, func() { x.Write(write) })
				})
			}
		}
	}
}

func TestXOFReset(t *testing.T) {
	for _, v := range streamXOFs {
		// -1 means reset while absorbing; 0 resets after Read(nil).
		for _, readBeforeReset := range []int{-1, 0, 1, v.rate, v.rate + 1} {
			t.Run(fmt.Sprintf("%s/read=%d", v.name, readBeforeReset), func(t *testing.T) {
				defer failUnfinished(t)
				x := v.newXOF()
				writeStream(t, x, streamInput(v.rate+3))
				if readBeforeReset >= 0 {
					readStream(t, x, readBeforeReset)
				}
				x.Reset()
				input := []byte("message after reset")
				writeStream(t, x, input)
				if got := readStream(t, x, 2*v.rate+5); !bytes.Equal(got, v.want(input, len(got))) {
					t.Fatal("Reset did not restore the initial variant/state")
				}
				x.Reset()
				if x.BlockSize() != v.rate || !bytes.Equal(readStream(t, x, 33), v.want(nil, 33)) {
					t.Fatal("Reset after squeezing did not restore empty input")
				}
			})
		}
	}
}

func TestXOFOwnership(t *testing.T) {
	for _, v := range streamXOFs {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			backing := streamInput(v.rate + 3 + 19)
			before := bytes.Clone(backing)
			x := v.newXOF()
			writeStream(t, x, backing[:v.rate+3])
			if !bytes.Equal(backing, before) {
				t.Fatal("Write changed input or spare capacity")
			}
			for i := range backing {
				backing[i] ^= 0xff
			}
			out := bytes.Repeat([]byte{0xa5}, 3+v.rate+1+5)
			n, err := x.Read(out[3 : 3+v.rate+1])
			if n != v.rate+1 || err != nil {
				t.Fatalf("Read = %d, %v", n, err)
			}
			want := v.want(before[:v.rate+3], 2*v.rate+8)
			if !bytes.Equal(out[3:3+n], want[:n]) ||
				!bytes.Equal(out[:3], bytes.Repeat([]byte{0xa5}, 3)) ||
				!bytes.Equal(out[3+n:], bytes.Repeat([]byte{0xa5}, 5)) {
				t.Fatal("Read retained input or wrote outside the output slice")
			}
			for i := 3; i < 3+n; i++ {
				out[i] ^= 0xff
			}
			outBeforeNextRead := bytes.Clone(out)
			if !bytes.Equal(readStream(t, x, len(want)-n), want[n:]) ||
				!bytes.Equal(out, outBeforeNextRead) {
				t.Fatal("Read retained caller output storage or restarted the stream")
			}
		})
	}
}

func TestXOFIndependentInstances(t *testing.T) {
	for _, v := range streamXOFs {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			a, b := v.newXOF(), v.newXOF()
			writeStream(t, a, []byte("a"))
			writeStream(t, b, []byte("b"))
			wantA, wantB := v.want([]byte("a"), 50), v.want([]byte("b"), 50)
			if !bytes.Equal(readStream(t, a, 17), wantA[:17]) ||
				!bytes.Equal(readStream(t, b, 50), wantB) ||
				!bytes.Equal(readStream(t, a, 33), wantA[17:]) {
				t.Fatal("instances share output state")
			}
		})
	}
}

func TestXOFReaderIntegration(t *testing.T) {
	for _, v := range streamXOFs {
		t.Run(v.name, func(t *testing.T) {
			defer failUnfinished(t)
			input := streamInput(3*v.rate + 17)
			x := v.newXOF()
			if n, err := io.Copy(x, bytes.NewReader(input)); n != int64(len(input)) || err != nil {
				t.Fatalf("io.Copy = %d, %v", n, err)
			}
			outputLength := 2*v.rate + 5
			first, err := io.ReadAll(io.LimitReader(x, int64(outputLength)))
			if err != nil || len(first) != outputLength {
				t.Fatalf("limited ReadAll: len=%d err=%v", len(first), err)
			}
			last := make([]byte, 31)
			if n, err := io.ReadFull(x, last); n != len(last) || err != nil {
				t.Fatalf("ReadFull = %d, %v", n, err)
			}
			if !bytes.Equal(append(first, last...), v.want(input, outputLength+len(last))) {
				t.Fatal("io.Reader integration lost output continuity")
			}
		})
	}
}
