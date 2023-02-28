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
	var dsa crypto.DSAPerUserParams
	var kk bi.Int
	found := false
	r, _ := bi.FromString("548099063082341131477253921760299949438196259240", 10)
	s, _ := bi.FromString("857042759984254168557880549501802188789837994940", 10)
	for k := 1; k < 1<<16; k++ {
		ki := bi.FromInt(k)
		x := ki.Mul(s).Sub(hi).Mul(crypto.ModInv(r, q)).Mod(q)
		d := crypto.DSAPerUserParams{
			DSAParams: crypto.DSAParams{P: p, Q: q, G: g},
			X:         x,
			Y:         y,
			H:         sh,
		}
		ri, si := d.SignWithK([]byte(msg), ki)
		if ri.Equal(r) && si.Equal(s) {
			sh.Reset()
			sh.Write([]byte(x.Text(16)))
			want := "0954edd5e0afe5542a4adf012611a91912a3ec16"
			got := utils.ToHexString(sh.Sum(nil))
			if got != want {
				continue
			} else {
				fmt.Printf("Private Key: 0x%s\n", x)
				found = true
				dsa = d
				kk = ki
				break
			}
		}
	}
	if !found {
		fmt.Println("failed")
	}
	r, s = dsa.SignWithK([]byte(msg), kk)
	fmt.Println(r)
	fmt.Println(s)
}

func Solve6_44() {
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

	y := readHex(`2d026f4bf30195ede3a088da85e398ef869611d0f68f07
	13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
	5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
	f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
	f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
	2971c3de5084cce04a2e147821`)

	type signMsg struct {
		msg string
		s   bi.Int
		r   bi.Int
		m   []byte
		hi  bi.Int
	}

	var msgs []signMsg
	sh := sha1.New()

	scanner := utils.GetFileScanner("inputs/6-44.txt")
	for scanner.Scan() {
		msg := scanner.Text()[len("msg: "):]
		scanner.Scan()
		s, _ := bi.FromString(scanner.Text()[len("s: "):], 10)
		scanner.Scan()
		r, _ := bi.FromString(scanner.Text()[len("r: "):], 10)
		scanner.Scan()
		m := utils.FromHexString(scanner.Text()[len("m: "):])
		sm := signMsg{msg: msg, s: s, r: r, m: m, hi: bi.FromBytes(m)}
		sh.Reset()
		sh.Write([]byte(msg))
		if !bytes.Equal(sh.Sum(nil), sm.m) {
			fmt.Println(msg, utils.ToHexString(m))
			fmt.Println("failed to parse input")
			return
		}
		msgs = append(msgs, sm)
	}

	/* Consider k is repeated in msgs[i] and msgs[j]
	Find corresponding k.
	Given k find the private key
	Check if the two signatures match showing that k was correct
	*/
	for i := 0; i < len(msgs); i++ {
		for j := i + 1; j < len(msgs); j++ {
			sdiff := msgs[i].s.Sub(msgs[j].s).Mod(q)
			mdiff := msgs[i].hi.Sub(msgs[j].hi).Mod(q)
			k := mdiff.Mul(crypto.ModInv(sdiff, q)).Mod(q)
			x := msgs[i].s.Mul(k).Sub(msgs[i].hi).Mul(crypto.ModInv(msgs[i].r, q)).Mod(q)
			dsa := crypto.DSAPerUserParams{
				DSAParams: crypto.DSAParams{
					P: p,
					Q: q,
					G: g,
				},
				Y: y,
				X: x,
				H: sh,
			}
			r1, s1 := dsa.SignWithK([]byte(msgs[i].msg), k)
			r2, s2 := dsa.SignWithK([]byte(msgs[j].msg), k)
			if r1.Equal(msgs[i].r) && s1.Equal(msgs[i].s) && r2.Equal(msgs[j].r) && s2.Equal(msgs[j].s) {
				sh.Reset()
				sh.Write([]byte(x.Text(16)))
				h := utils.ToHexString(sh.Sum(nil))
				fmt.Println(h)
				fmt.Println("ca8f6f7c66fa362d40760d135b763eb8527d3d52")
				fmt.Println(x)
				return
			}
		}
	}
	fmt.Println("FAILED")
}

func Solve6_45() {
	dsa, _ := crypto.GenerateDSAParams(1024, 160)
	dsa.G = bi.Zero

	h := sha1.New()
	dsaU := dsa.GenKey(h)

	msg1 := "Hello, world"
	msg2 := "Goodbye, world"
	// this will go into an infinite loop since y = 0^k is always 0
	// r1, s1 := dsaU.Sign([]byte(msg1))
	// r2, s2 := dsaU.Sign([]byte(msg2))

	dsa.G = dsa.P.Add(bi.One)
	dsaU = dsa.GenKey(h)

	// here g = 1 => y = 1 & r = 1
	// any exponent of g and y will always be 1
	r := bi.One
	z := bi.RandInt(dsaU.Q)
	s := crypto.ModInv(z, dsaU.Q)

	fmt.Println(dsaU.Verify([]byte(msg1), r, s))
	fmt.Println(dsaU.Verify([]byte(msg2), r, s))

}

func Solve6_46() {
	msg := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	msgB := utils.FromBase64String(msg)
	rsa := crypto.NewRSAN((2048) / 16)
	oddOracle := func(b []byte) bool {
		pt := rsa.Decrypt(b)
		return bi.FromBytes(pt).Mod(bi.Two).Equal(bi.One)
	}
	cipher := rsa.Encrypt(msgB)
	ci := bi.FromBytes(cipher)
	lo, hi := bi.Zero, rsa.N
	msgParity := bi.Zero
	if oddOracle(cipher) {
		msgParity = bi.One
	}
	for lo.Cmp(hi) < 0 {
		mid := lo.Add(hi).Div(bi.Two)
		mul := rsa.N.Div(mid)
		t := bi.FromBytes(rsa.Encrypt(mul.Bytes())).Mul(ci).Mod(rsa.N)
		isOdd := oddOracle(t.Bytes())
		expectedParity := bi.Zero
		if mul.Mod(bi.Two).Equal(bi.One) && msgParity.Equal(bi.One) {
			expectedParity = bi.One
		}
		foundParity := bi.Zero
		if isOdd {
			foundParity = bi.One
		}
		if expectedParity.Equal(foundParity) {
			hi = mid
		} else {
			lo = mid.Add(bi.One)
		}
	}
	fmt.Println(string(hi.Bytes()))
	fmt.Println(string(msgB))
}

func Solve6_48(msg string) string {
	rsa := crypto.NewRSAN(768 / (16))
	oracle := func(b []byte) bool {
		return crypto.ValidPadding(b, rsa)
	}
	c := crypto.EncryptRSAWithPadding([]byte(msg), rsa)
	m := crypto.BreakRSAWithPaddingOracle(c, oracle, rsa)
	return string(crypto.RemovePadding(m))
}
