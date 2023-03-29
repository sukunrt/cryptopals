package crypto

import (
	"bytes"
	"testing"

	"github.com/sukunrt/cryptopals/utils"
)

func TestMDWriteBlock(t *testing.T) {
	b1 := utils.RandBytes(AESBlockSize)
	b2 := utils.RandBytes(AESBlockSize)
	b3 := utils.ConcatBytes(b1, b2)

	md1 := NewMD(16)
	md2 := NewMD(16)

	md1.WriteBlock(b1)
	h1, err := md1.WriteBlock(b2)
	if err != nil {
		t.Fatalf("should not error here %s", err)
	}

	h2, err := md2.WriteBlock(b3)
	if err != nil {
		t.Fatalf("should not error here %s", err)
	}

	if !bytes.Equal(h1, h2) {
		t.Fatalf("hash should have been equal")
	}
}

func TestExpandableMessages(t *testing.T) {
	md := NewMD(32)

	msgs := MakeExpandableMessages(md, 3)
	if len(msgs) != 3 {
		t.Fatalf("expected 3 msgs: got %d", len(msgs))
	}

	var h1 []byte
	var err error
	for i := 0; i < 3; i++ {
		h1, err = md.WriteBlock(msgs[i][0])
		if err != nil {
			t.Fatalf("didn't expect to error %s", err)
		}
	}

	var h2 []byte
	combinations := [][3]int{{0, 0, 0}, {0, 0, 1}, {0, 1, 0}, {0, 1, 1}, {1, 0, 0}, {1, 0, 1}, {1, 1, 0}, {1, 1, 1}}
	for _, comb := range combinations {
		md.Reset()
		for i := 0; i < 3; i++ {
			h2, err = md.WriteBlock(msgs[i][comb[i]])
			if err != nil {
				t.Fatalf("didn't expect to error %s", err)
			}
		}
		if !bytes.Equal(h1, h2) {
			t.Fatalf("expected hashes to be equal, mismatch in 0,0,0 and %v", comb)
		}
	}

}

func TestMDCollision(t *testing.T) {
	md := NewMD(32)
	b := utils.RandBytes(2048 * AESBlockSize)
	bb := FindCollisions(b, md)
	md.Reset()
	h1 := md.Hash(bb, make([]byte, md.Hsz))
	h2 := md.Hash(b, make([]byte, md.Hsz))
	if !bytes.Equal(h1, h2) || bytes.Equal(b, bb) {
		t.Fatalf("hash should be equal")
	}
}

func TestSTree(t *testing.T) {
	md := NewMD(32)
	k := 5
	s := makeSTree(k, md)
	for j := 0; j < 32; j++ {
		path := make([][]byte, 0)
		st := s.states[0][j]
		nxt := string(st)
		for i := 0; i < k; i++ {
			path = append(path, s.nm[i][nxt])
			nxt = s.hm[i][string(nxt)]
		}
		p := utils.ConcatBytes(path...)
		p = utils.PadBytes(p, AESBlockSize)
		md.Set(st)
		h, err := md.WriteBlock(p)
		if err != nil {
			t.Errorf("failed to hash")
		}
		if !bytes.Equal(s.Hash, h) {
			t.Errorf("failure, start pos %d", j)
		}
	}
}

func TestNostradamusAttack(t *testing.T) {
	md := NewMD(32)
	f := NostradamusAttack(md)
	m := []byte("1-0|2-3|2-0|3-5|5-3|4-4")
	msg, hash := f(m)
	md.Reset()
	h := md.Hash(msg, make([]byte, 0))
	if !bytes.Equal(h, hash) {
		t.Errorf("expected hashes to be equal")
	}
}
