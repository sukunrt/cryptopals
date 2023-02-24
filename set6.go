package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	bi "github.com/sukunrt/bigint"
	"github.com/sukunrt/cryptopals/crypto"
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
