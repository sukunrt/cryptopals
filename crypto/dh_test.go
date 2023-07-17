package crypto

import (
	"crypto/sha256"
	"fmt"
	"testing"

	bi "github.com/sukunrt/bigint"
)

func TestDHSmallSubgroup(t *testing.T) {
	tests := []struct {
		P    bi.Int
		O    bi.Int
		want []DHGroup
	}{
		{
			P:    bi.FromInt(31),
			O:    bi.FromInt(5),
			want: []DHGroup{{P: bi.FromInt(31), O: bi.Two}, {P: bi.FromInt(31), O: bi.Three}},
		},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			ch := DHSmallSubgroup(tt.P, tt.O, tt.P.Int()-1)
			for _, w := range tt.want {
				got := <-ch
				if !got.P.Equal(w.P) || !got.O.Equal(w.O) {
					t.Errorf("struct mismatch got: %s want: %s", got, w)
				}
				h := got.G
				if !bi.Exp(h, w.O, w.P).Equal(bi.One) {
					t.Errorf("elem group is not 1 got: %s want: %s", got, w)
				}
				for i := 1; i < w.O.Int(); i++ {
					if bi.Exp(h, bi.FromInt(i), w.P).Equal(bi.One) {
						t.Errorf("elem group is %d, want: %s, got: %s want: %s", i, w.O, got, w)
					}
				}

			}
		})
	}
}

func TestDHSmallSubgroupAttack(t *testing.T) {
	tests := []struct {
		P, Y, O, G bi.Int
	}{
		{P: bi.FromInt(31), O: bi.FromInt(5), G: bi.FromInt(2), Y: bi.FromInt(4)},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			hash := sha256.New()
			got := DHSmallSubgroupAttack(tt.P, tt.G, tt.O, func(gx bi.Int) HandshakeMsg {
				msg := "Hello World"
				K := bi.Exp(gx, tt.Y, tt.P)
				hash.Reset()
				hash.Write(append(K.Bytes(), []byte(msg)...))
				mac := hash.Sum(nil)
				return HandshakeMsg{
					Msg: msg,
					Mac: mac,
				}
			})
			if !got.Equal(tt.Y) {
				t.Fatalf("priv key mismatch got: %s want: %s", got, tt.Y)
			}
		})
	}
}
