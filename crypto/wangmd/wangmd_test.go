package wangmd

import (
	"bytes"
	"testing"

	"github.com/sukunrt/cryptopals/utils"
	"golang.org/x/crypto/md4"
)

func TestGenCollision(t *testing.T) {
	w := &WangMD4{}
	x1, x2, err := w.GenCollision()
	if err != nil {
		t.Fatalf("didn't expect to timeout")
	}

	md := md4.New()
	md.Write(x1)
	h1 := md.Sum(nil)
	md.Reset()
	md.Write(x2)
	h2 := md.Sum(nil)
	md.Reset()

	if !bytes.Equal(h1, h2) {
		t.Fatalf("didn't expect to fail")
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
