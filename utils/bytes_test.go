package utils

import (
	"bytes"
	"testing"
)

func TestCountSetBits(t *testing.T) {
	cases := []byte{0, 1, 2, 3, 7, 8, 15, 255}
	want := []int{0, 1, 1, 2, 3, 1, 4, 8}
	for i := 0; i < len(cases); i++ {
		if CountSetBits(cases[i]) != want[i] {
			t.Fatalf("Count bites failed for %d", cases[i])
		}
	}
}

func TestPadBytes(t *testing.T) {
	s := []byte("YELLOW SUBMARINE")
	b := []byte("YELLOW SUBMARINE")
	b = append(b, []byte{4, 4, 4, 4}...)
	if !bytes.Equal(PadBytes(s, 20), b) {
		t.Fatalf("padding bytes failed for Yellow Submarine and 20")
	}
}

func TestRemovePad(t *testing.T) {
	s := []byte("YELLOW SUBMARINE")
	if !bytes.Equal(RemovePad(PadBytes(s, 20)), s) {
		t.Fatalf("Remove padding bytes failed for Yellow Submarine and 20")
	}
}
