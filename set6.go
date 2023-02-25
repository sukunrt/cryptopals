package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"strings"

	bi "github.com/sukunrt/bigint"
	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

func Solve6_41() {
	msgs := []string{"hello", "world", "smallstrings", "with spaces", "long string also"}
	for _, m := range msgs {
		out := crypto.UnPaddedRSAOracle(m)
		if out != m {
			fmt.Println(m, "FAILED")
			return
		}
	}
	fmt.Println("SUCCESS")
}

func Solve6_42(m string) bool {
	r := crypto.NewRSAN(64)
	msg := "hello world"
	signature := r.Sign([]byte(msg))
	if !crypto.VerifyRSASignatureCorrect([]byte(msg), signature, r) {
		fmt.Println("failed", msg)
		return false
	}
	if !crypto.VerifyRSASignatureInCorrect([]byte(msg), signature, r) {
		fmt.Println("failed", msg)
		return false
	}

	block := make([]byte, r.Sz)
	block[0] = 0
	block[1] = 1
	block[2] = 0xFF
	block[3] = 0
	block[4] = 0xA
	block[5] = 0xB
	sha := sha256.New()
	sha.Write([]byte(m))
	copy(block[6:], sha.Sum(nil))

	target := bi.FromBytes(block)
	st, ed := bi.Zero, r.N
	for ed.Cmp(st.Add(bi.One)) > 0 {
		mi := st.Add(ed).Div(bi.Two)
		cb := mi.Mul(mi).Mul(mi)
		if cb.Equal(target) {
			ed = mi
			break
		} else if cb.Cmp(target) > 0 {
			ed = mi
		} else {
			st = mi
		}
	}
	cb := make([]byte, 1)
	cb = append(cb, ed.Mul(ed).Mul(ed).Bytes()...) //

	if !bytes.Equal(cb[:6+32], block[:6+32]) {
		fmt.Println(cb[:40], block[:40])
		panic("cbrt failed")
	}

	if !crypto.VerifyRSASignatureInCorrect([]byte(m), ed.Bytes(), r) {
		fmt.Println("forgery failed")
		return false
	}
	if crypto.VerifyRSASignatureCorrect([]byte(m), ed.Bytes(), r) {
		fmt.Println("correct algor is incorrect")
		return false
	}
	return true
}

func readHex(s string) bi.Int {
	for _, c := range []string{"\n", "\t", " "} {
		s = strings.ReplaceAll(s, c, "")
	}
	return bi.FromBytes(utils.FromHexString(s))
}

func Solve6_43() {
	p := readHex(`800000000000000089e1855218a0e7dac38136ffafa72eda7
	859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
	2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
	ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
	b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
	1a584471bb1`)
	q := readHex(`f4f47f05794b256174bba6e9b396a7707e563c5b`)
	g := readHex(`5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
	458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
	322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
	0f5b64c36b625a097f1651fe775323556fe00b3608c887892
	878480e99041be601a62166ca6894bdd41a7054ec89f756ba
	9fc95302291`)
	msg := `For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
`
	sh := sha1.New()
	sh.Write([]byte(msg))
	shVal := sh.Sum(nil)
	if utils.ToHexString(shVal) != "d2d0714f014a9784047eaeccf956520045c45265" {
		panic("hashing failed")
	}

	sh.Reset()
	sh.Write([]byte(msg))
	h := sh.Sum(nil)
	hi := bi.FromBytes(h)

	y := readHex(`084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
	abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
	e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
	1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
	bb283e6633451e535c45513b2d33c99ea17`)
	r := bi.FromString("548099063082341131477253921760299949438196259240")
	s := bi.FromString("857042759984254168557880549501802188789837994940")
	for k := 1; k < 1<<16; k++ {
		ki := bi.FromInt(k)
		x := ki.Mul(s).Sub(hi).Mul(crypto.ModInv(r, q)).Mod(q)
		d := crypto.DSAPerUserParams{
			DSAParams: crypto.DSAParams{P: p, Q: q, G: g},
			X:         x,
			Y:         y,
		}
		ri, si := d.SignWithK([]byte(msg), ki)
		if ri.Equal(r) && si.Equal(s) {
			sh = sha1.New()
			sh.Write([]byte(x.Text(16)))
			want := "0954edd5e0afe5542a4adf012611a91912a3ec16"
			got := utils.ToHexString(sh.Sum(nil))
			if got != want {
				fmt.Println("failed")
				continue
			} else {
				fmt.Println(x)
				fmt.Println(got)
				fmt.Println(want)
				fmt.Println("found IT")
			}
			return
		}
	}
	fmt.Println("failed")
}
