package sha3

import (
	"encoding/hex"
	"encoding/json"
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
