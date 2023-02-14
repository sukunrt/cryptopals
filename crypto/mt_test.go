package crypto

import (
	"math/rand"
	"testing"
)

func checkOpAndRev(op, rev func(int) int) (bool, int) {
	for i := 0; i < 1000; i++ {
		x := rand.Intn(1 << 31)
		if x != rev(op(x)) {
			return false, x
		}
	}
	return true, -1
}

func TestRevOpA(t *testing.T) {
	success, x := checkOpAndRev(OpA, RevOpA)
	if !success {
		t.Fatalf("OpA: Failed for %d", x)
	}
}

func TestRevOpB(t *testing.T) {
	success, x := checkOpAndRev(OpB, RevOpB)
	if !success {
		t.Fatalf("OpB: Failed for %d", x)
	}
}

func TestRevOpC(t *testing.T) {
	success, x := checkOpAndRev(OpC, RevOpC)
	if !success {
		t.Fatalf("OpC: Failed for %d", x)
	}
}

func TestRevOpD(t *testing.T) {
	success, x := checkOpAndRev(OpD, RevOpD)
	if !success {
		t.Fatalf("OpD: Failed for %d", x)
	}
}
