package wangmd

import (
	"bytes"
	"testing"

	"github.com/sukunrt/cryptopals/hashing/md4"
	"github.com/sukunrt/cryptopals/utils"
)

func TestHash(t *testing.T) {
	w := &WangMD4{}
	blk := utils.RepBytes('1', 512/8)
	sm := w.HashTransform(blk)
	m := md4.New()
	m.Write(blk)
	sm2 := m.CSum()
	if !bytes.Equal(sm, sm2) {
		t.Fatalf("failed checksum")
	}
}
