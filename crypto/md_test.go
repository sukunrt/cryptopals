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
	md := NewMD(16)
	b := utils.RandBytes(32 * AESBlockSize)
	bb := FindCollisions(b, md)
	md.Reset()
	h1 := md.Hash(bb, make([]byte, md.Hsz))
	h2 := md.Hash(b, make([]byte, md.Hsz))
	if !bytes.Equal(h1, h2) || bytes.Equal(b, bb) {
		t.Fatalf("hash should be equal")
	}
}
