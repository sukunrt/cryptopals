package crypto

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/sukunrt/cryptopals/mt"
)

const _l = 18
const _t, _c = 15, 0xEFC60000
const _s, _b = 7, 0x9D2C5680
const _u, _d = 11, 0xFFFFFFFF

/*
	y := mt.mt[mt.idx]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)
*/
// ReverseTemper reverses the original tempering done with MT19937
func ReverseTemper(y int) int {
	return RevOpD(RevOpC(RevOpB(RevOpA(y))))
}

func OpA(y int) int {
	return y ^ (y >> _l)
}

func RevOpA(y int) int {
	return OpA(y)
}

func OpB(y int) int {
	return y ^ ((y << _t) & _c)
}

func RevOpB(y int) int {
	return OpB(y)
}

func OpC(y int) int {
	return y ^ ((y << _s) & _b)
}

func RevOpC(y int) int {
	y = y ^ ((y << _s) & _b)
	y = y ^ (((y << (2 * _s)) & _d) & (_b & (_b << _s) & _d))
	y = y ^ (((y << (4 * _s)) & _d) & (_b & (_b << _s) & (_b << (2 * _s)) & _d))
	return y
}

func OpD(y int) int {
	return y ^ ((y >> _u) & _d)
}

func RevOpD(y int) int {
	y = y ^ (y >> _u)
	y = y ^ (y >> (2 * _u))
	return y
}

type MTCipher struct {
	seed int
}

func NewMTCipher(seed int) MTCipher {
	return MTCipher{seed}
}

func (mtc MTCipher) Encrypt(b []byte) []byte {
	m := mt.NewMTRNG(mtc.seed)
	cipherText := make([]byte, len(b))
	for i := 0; i < len(cipherText); i += 4 {
		key := m.Int()
		for j := 0; j < 4 && i+j < len(cipherText); j++ {
			cipherText[i+j] = b[i+j] ^ byte((key&((0xFF)<<(3-j)))>>(3-j))
		}
	}
	return cipherText
}

func (mtc MTCipher) Decrypt(b []byte) []byte {
	return mtc.Encrypt(b)
}

// Bytes returns n bytes from the random number generator
func (mtc MTCipher) Bytes(n int) []byte {
	res := make([]byte, ((n+3)/4)*4)
	mt := mt.NewMTRNG(mtc.seed)
	for i := 0; i < n; i += 4 {
		x := mt.Int()
		binary.BigEndian.PutUint32(res[i:], uint32(x))
	}
	return res[:n]
}

func BreakMTCipherToken(token []byte) int {
	now := time.Now().Unix()
	for i := 0; i < 100_000_000; i++ {
		now--
		mtc := NewMTCipher(int(now))
		tryToken := mtc.Bytes(10 * len(token))
		if bytes.Contains(tryToken, token) {
			return int(now)
		}
	}
	return -1
}
