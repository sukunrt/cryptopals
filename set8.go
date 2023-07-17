package main

import (
	"crypto/sha256"
	"fmt"

	bi "github.com/sukunrt/bigint"
	"github.com/sukunrt/cryptopals/crypto"
)

func Solve8_57() {
	success := true
	for ii := 0; ii < 10; ii++ {
		p, _ := bi.FromString("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)
		g, _ := bi.FromString("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)
		o, _ := bi.FromString("236234353446506858198510045061214171961", 10)
		//		y := bi.RandInt(o).Add(bi.One)
		y, _ := bi.FromString("153288953611337440041334918882355340049", 10)
		hash := sha256.New()
		handshakeF := func(gx bi.Int) crypto.HandshakeMsg {
			msg := "crazy flamboyant for the rap enjoyment"
			K := bi.Exp(gx, y, p)
			hash.Reset()
			hash.Write(append(K.Bytes(), []byte(msg)...))
			mac := hash.Sum(nil)
			return crypto.HandshakeMsg{
				Msg: msg,
				Mac: mac,
			}
		}
		yy := crypto.DHSmallSubgroupAttack(p, g, o, handshakeF)
		if !y.Equal(yy) {
			fmt.Println("FAILED", ii, y)
			success = false
			break
		}
	}
	if success {
		fmt.Println("SUCCESS!")
	}

}
