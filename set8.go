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
		y := bi.RandInt(o).Add(bi.One)
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
				PK:  K,
			}
		}
		yy, _ := crypto.DHSmallSubgroupAttack(p, g, o, handshakeF)
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

func Solve8_58() {
	success := true
	for ii := 0; ii < 2; ii++ {
		p, _ := bi.FromString("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623", 10)
		g, _ := bi.FromString("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357", 10)
		o, _ := bi.FromString("335062023296420808191071248367701059461", 10)
		y := bi.RandInt(o).Add(bi.One)
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
				PK:  bi.Exp(g, y, p),
			}
		}
		yy := crypto.DHSmallSubgroupWithPollardKangarooAttack(p, g, o, handshakeF)
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
