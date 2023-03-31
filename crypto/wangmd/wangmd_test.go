package wangmd

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/sukunrt/cryptopals/utils"
)

func TestGenCollision(t *testing.T) {
	rand.Seed(82734895274358902)
	w := &WangMD4{}
	x1, x2 := w.GenCollision()
	if !bytes.Equal(x1, x2) {
		t.Fatalf("failed")
	}

}

func TestPacking(t *testing.T) {
	for i := 0; i < 100; i++ {
		msg := utils.RandBytes(512 / 8)
		if !bytes.Equal(msg, pack(unpack(msg))) {
			t.Errorf("packing unpacking shoule be same")
		}
	}
}
