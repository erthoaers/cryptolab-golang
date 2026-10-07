package sha3

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

func failUnfinished(t *testing.T) {
	t.Helper()
	if r := recover(); r != nil {
		if message, ok := r.(todo); ok {
			t.Fatalf("unfinished exercise: %s", message)
		}
		panic(r)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type vector struct{ Source, Case, Message, Output string }

func vectors(t *testing.T, algorithm string) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + algorithm + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Standard, Archive string
		Vectors           []vector
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Standard == "" || fixture.Archive == "" || len(fixture.Vectors) < 10 {
		t.Fatal("incomplete fixtures")
	}
	return fixture.Vectors
}

// streamInput is deterministic synthetic data, not an official NIST vector.
func streamInput(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*37 + 11)
	}
	return out
}

func writeStream(t *testing.T, w io.Writer, input []byte) {
	t.Helper()
	if n, err := w.Write(input); n != len(input) || err != nil {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(input))
	}
}

func writeStreamChunks(t *testing.T, w io.Writer, input []byte, chunk int) {
	t.Helper()
	writeStream(t, w, nil)
	for len(input) > 0 {
		n := min(chunk, len(input))
		writeStream(t, w, input[:n])
		writeStream(t, w, []byte{})
		input = input[n:]
	}
}

func readStream(t *testing.T, r io.Reader, length int) []byte {
	t.Helper()
	// Use nil for an empty request to exercise the phase transition explicitly.
	var out []byte
	if length > 0 {
		out = make([]byte, length)
	}
	if n, err := r.Read(out); n != len(out) || err != nil {
		t.Fatalf("Read = %d, %v; want %d, nil", n, err, len(out))
	}
	return out
}

func requireStreamPanic(t *testing.T, operation func()) {
	t.Helper()
	defer func() {
		r := recover()
		if message, ok := r.(todo); ok {
			t.Fatalf("unfinished exercise: %s", message)
		}
		if r == nil {
			t.Fatal("Write after Read did not panic")
		}
	}()
	operation()
}
